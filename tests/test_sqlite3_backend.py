import os
import sqlite3
from collections import namedtuple
from ipaddress import IPv4Address, IPv6Address

import numpy as np
import pandas as pd
import pytest

from tmautils.enrich_ip._sqlite_storage import SqliteDatabase


Mode = namedtuple("Mode", "offload buffering label")

# Baseline direct, no buffering
MODE_DIRECT = Mode(False, False, "direct")

# Exercise IPC path without buffering
MODE_WORKER = Mode(True,  False, "worker")

# Smoke buffered path (per-query flush keeps reads deterministic)
MODE_BUFFERED_DIRECT = Mode(False, True,  "buffered_direct")

# Exercise buffered path through worker as well
MODE_BUFFERED_WORKER = Mode(True,  True,  "buffered_worker")

# Groups
CRUD_MODES = [MODE_DIRECT, MODE_WORKER, MODE_BUFFERED_WORKER]
# no need to test IPC here
TYPECAST_MODES = [MODE_DIRECT, MODE_BUFFERED_DIRECT]
DDL_MODES = [MODE_DIRECT]  # schema/indices once is enough


# ----------------------------------------------------------------------
# Fixture: db_maker
#   - Configures thresholds so tests never rely on time-based flushing.
#   - If buffering is enabled, we set:
#       * a huge row_threshold (so inserts won’t auto-flush)
#       * a huge flush interval (so the background ticker won’t kick in)
#     and then rely on either per-query `flush_before_query` or `force_flush=True` in tests.
# ----------------------------------------------------------------------
@pytest.fixture
def db_maker(tmp_path):
    created = []

    def make_db(filename: str, mode: Mode) -> SqliteDatabase:
        db_file = tmp_path / filename
        # Keep deterministic behavior in buffered tests:
        row_threshold = 1_000_000 if mode.buffering else 1_000
        # effectively disables timed flushes
        flush_interval = 3_600.0 if mode.buffering else 30.0

        db = SqliteDatabase(
            str(db_file),
            uri=False,
            offload_to_worker=mode.offload,
            write_buffering=mode.buffering,
            write_buf_row_threshold=row_threshold,
            write_buf_flush_interval_sec=flush_interval,
        )
        created.append(db)
        return db

    yield make_db

    # Close all DBs to shut down worker processes cleanly
    for db in created:
        try:
            db.close()
        except Exception:
            pass


# ---------------------------- CRUD / IPC -------------------------------

@pytest.mark.parametrize("mode", CRUD_MODES, ids=[m.label for m in CRUD_MODES])
def test_single_table_crud(db_maker, mode):
    manager = db_maker("test.db", mode)

    schema = {"id": int, "ip": IPv4Address, "name": str}
    qualifiers = {"id": "PRIMARY KEY AUTOINCREMENT"}
    constraints = ["UNIQUE(name)"]
    indices = [["ip"]]

    users = manager.register_table(
        "users", schema,
        qualifiers=qualifiers,
        table_constraints=constraints,
        indices=indices
    )

    df_insert = pd.DataFrame({
        "ip": ["192.168.0.1", "10.0.0.2"],
        "name": ["Alice", "Bob"]
    })
    # In worker modes, this blocks on the RPC return.
    # Buffered modes rely on per-query flush_before_query=True (the default) to get fresh data.
    users.insert_df(df_insert, wait_for_worker=True)

    df_all = users.query_all()
    assert set(df_all.columns) == {"id", "ip", "name"}
    assert list(df_all["id"]) == [1, 2]
    assert df_all.loc[0, "ip"] == IPv4Address("192.168.0.1")
    assert set(df_all["name"]) == {"Alice", "Bob"}

    df_dup = pd.DataFrame({"ip": ["127.0.0.1"], "name": ["Alice"]})
    with pytest.raises(sqlite3.IntegrityError):
        # Force a flush so the integrity error surfaces immediately,
        # regardless of buffering.
        users.insert_df(df_dup, wait_for_worker=True, force_flush=True)


@pytest.mark.parametrize("mode", CRUD_MODES, ids=[m.label for m in CRUD_MODES])
def test_query_and_query_all(db_maker, mode):
    manager = db_maker("flows.db", mode)

    schema = {"src": IPv4Address, "dst": IPv4Address, "val": int}
    indices = [["val"]]
    flows = manager.register_table("flows", schema, indices=indices)

    df_flow = pd.DataFrame({
        "src": [f"1.1.1.{i}" for i in range(100)],
        "dst": [f"2.2.2.{i}" for i in range(100)],
        "val": list(range(100))
    })
    flows.insert_df(df_flow, wait_for_worker=True)

    sql = "SELECT * FROM flows WHERE val >= ? AND val < ?"
    df_filtered = flows.query(sql, params=(10, 20))
    assert df_filtered.shape[0] == 10
    assert set(df_filtered["val"]) == set(range(10, 20))

    df_all = flows.query_all()
    assert df_all.shape[0] == 100


# ---------------------------- TYPE CASTS -------------------------------

@pytest.mark.parametrize("mode", TYPECAST_MODES, ids=[m.label for m in TYPECAST_MODES])
def test_boolean_and_nullable(db_maker, mode):
    mgr = db_maker("bool.db", mode)

    schema = {"f": bool, "g": bool}
    qualifiers = {"g": "NOT NULL"}
    tbl = mgr.register_table("t_bool", schema, qualifiers=qualifiers)

    df = pd.DataFrame({
        "f": [True, False, pd.NA],
        "g": [True, False, True],
    }).astype({"f": "boolean", "g": "boolean"})
    tbl.insert_df(df, wait_for_worker=True)
    out = tbl.query_all()

    assert out["f"].dtype == "boolean"
    assert out["g"].dtype == "boolean"
    assert list(out["f"]) == [True, False, pd.NA]
    assert list(out["g"]) == [True, False, True]

    with pytest.raises(sqlite3.IntegrityError):
        # NOT NULL violation for g
        tbl.insert_df(
            pd.DataFrame({"f": [True], "g": [None]}).astype("boolean"),
            wait_for_worker=True,
            force_flush=True,
        )


@pytest.mark.parametrize("mode", TYPECAST_MODES, ids=[m.label for m in TYPECAST_MODES])
def test_datetime_and_nat(db_maker, mode):
    mgr = db_maker("dt.db", mode)

    schema = {"ts1": np.datetime64, "ts2": pd.Timestamp}
    tbl = mgr.register_table("t_dt", schema)

    now = pd.Timestamp("2025-01-01T12:00")
    df = pd.DataFrame({
        "ts1": [now.to_numpy(), np.datetime64("NaT")],
        "ts2": [now, pd.NaT],
    })
    tbl.insert_df(df, wait_for_worker=True)
    out = tbl.query_all()

    assert out["ts1"].dtype == "datetime64[ns]"
    assert out["ts2"].dtype == "datetime64[ns]"
    assert pd.isna(out.loc[1, "ts1"])
    assert pd.isna(out.loc[1, "ts2"])


@pytest.mark.parametrize("mode", TYPECAST_MODES, ids=[m.label for m in TYPECAST_MODES])
def test_ipaddr_and_null(db_maker, mode):
    mgr = db_maker("ip.db", mode)

    schema = {"a": IPv4Address, "b": IPv6Address}
    tbl = mgr.register_table("t_ip", schema)

    df = pd.DataFrame({
        "a": ["1.2.3.4", None],
        "b": ["2001:db8::1", pd.NA],
    })
    tbl.insert_df(df, wait_for_worker=True)
    out = tbl.query_all()

    assert isinstance(out.loc[0, "a"], IPv4Address)
    assert out.loc[1, "a"] is None
    assert isinstance(out.loc[0, "b"], IPv6Address)
    assert out.loc[1, "b"] in (None, pd.NA)


@pytest.mark.parametrize("mode", TYPECAST_MODES, ids=[m.label for m in TYPECAST_MODES])
def test_numpy_scalars(db_maker, mode):
    mgr = db_maker("num.db", mode)

    schema = {"i": int, "f": float}
    tbl = mgr.register_table("t_num", schema)

    df = pd.DataFrame({
        "i": np.array([1, 2, 3], dtype=np.int64),
        "f": np.array([0.1, 0.2, 0.3], dtype=np.float64),
    })
    tbl.insert_df(df, wait_for_worker=True)
    out = tbl.query_all()

    assert out["i"].dtype == "Int64"
    assert out["f"].dtype == "Float64"
    assert out["i"].tolist() == [1, 2, 3]
    assert np.allclose(out["f"].astype(float), [0.1, 0.2, 0.3])


# -------------------------- PARTIAL QUERY / DDL ------------------------

@pytest.mark.parametrize("mode", DDL_MODES, ids=[m.label for m in DDL_MODES])
def test_partial_query(db_maker, mode):
    mgr = db_maker("part.db", mode)

    schema = {"x": int, "y": str, "z": IPv4Address}
    tbl = mgr.register_table("t_p", schema)

    df = pd.DataFrame({
        "x": [10, 20],
        "y": ["foo", "bar"],
        "z": ["8.8.8.8", "1.1.1.1"]
    })
    tbl.insert_df(df, wait_for_worker=True)

    out = tbl.query("SELECT z, x FROM t_p WHERE x > ?", params=(10,))
    assert list(out.columns) == ["z", "x"]
    assert out["x"].tolist() == [20]
    assert isinstance(out.loc[0, "z"], IPv4Address)


@pytest.mark.parametrize("mode", DDL_MODES, ids=[m.label for m in DDL_MODES])
def test_index_creation(db_maker, mode):
    mgr = db_maker("idx.db", mode)

    schema = {"a": int, "b": int}
    idxs = [["a", "b"], ["b"]]
    tbl = mgr.register_table("t_idx", schema, indices=idxs)

    # PRAGMA via the table API
    pragma_df = tbl.query("PRAGMA index_list(t_idx);")
    got = set(pragma_df["name"])
    expected = {f"idx_t_idx_{'_'.join(i)}" for i in idxs}
    assert expected.issubset(got)


@pytest.mark.parametrize("mode", DDL_MODES, ids=[m.label for m in DDL_MODES])
def test_invalid_schema_and_qualifier(db_maker, mode):
    mgr = db_maker("bad.db", mode)

    with pytest.raises(TypeError):
        mgr.register_table("t_bad", {"foo": set})

    with pytest.raises(ValueError):
        mgr.register_table("t_bad2", {"a": int}, qualifiers={"a": "NOTVALID"})


if __name__ == "__main__":
    pytest.main(["-vv", "-rA", os.path.abspath(__file__)])
