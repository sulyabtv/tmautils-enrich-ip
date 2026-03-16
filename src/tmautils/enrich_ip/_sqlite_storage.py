# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Sulyab Thottungal Valapu

from typing import Optional, Dict
from ipaddress import IPv4Address, IPv6Address
from typing import Type, Any, Callable
import sqlite3
import pandas as pd
import numpy as np
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor
import threading
import warnings

from ._sqlite_helpers import SqliteWorkerHelper

from tmautils.core import (
    LogHelper, get_logger_from_helper,
    try_convert_ip,
)

# Globals
_sqlite3_global_lock = threading.Lock()
_sqlite3_conversions_registered = False


class SqliteTable:
    """
    A class to manage SQLite tables with a defined schema, including qualifiers, constraints, and indices.
    This class provides methods to create or verify a table, insert data from a pandas DataFrame,
    and query data using SQL and obtain results as a DataFrame.
    It tries to verify that the table schema matches the provided schema.

    Args:
        db (SqliteDatabase):
            The parent `SqliteDatabase` instance managing the connection.

        table_name (str):
            Name of the table to create or manage.

        schema (dict[str, Type[Any]]):
            Dictionary mapping column names to Python types.

        qualifiers (dict[str, str] | None):
            Optional dictionary mapping column names to SQLite qualifiers (e.g., "NOT NULL").

        table_constraints (list[str] | None):
            Optional list of table-level constraints (e.g., "PRIMARY KEY").

        indices (list[list[str]] | None):
            Optional list of lists, where each inner list contains column names for an index.
    """

    # List of allowed SQLite qualifiers
    ALLOWED_QUALIFIERS = (
        "NOT NULL",
        "NULL",
        "PRIMARY KEY",
        "UNIQUE",
        "CHECK",
        "DEFAULT",
        "COLLATE",
        "REFERENCES",
    )
    # Mapping of Python types to SQLite column types
    PYTHON_TO_SQLITE: dict[Type[Any], str] = {
        int: "INTEGER",
        float: "REAL",
        str: "TEXT",
        bytes: "BLOB",

        # Custom types
        bool: "BOOL",
        IPv4Address: "IPADDR",
        IPv6Address: "IPADDR",
        np.datetime64: "TIMESTAMP",
        pd.Timestamp: "TIMESTAMP",
    }
    # Teaches sqlite3 how to convert Python types to SQLite types
    SQLITE3_ADAPTERS: dict[Type[Any], Callable] = {
        # Boolean
        bool: lambda b: int(b),
        np.bool_: lambda b: int(b),

        # IP Addresses
        IPv4Address: lambda ip: ip.packed,
        IPv6Address: lambda ip: ip.packed,

        # Timestamps
        np.datetime64: lambda ts: pd.to_datetime(ts).isoformat(),
        pd.Timestamp: lambda ts: ts.isoformat(),

        # N/A types
        type(pd.NA): lambda na: None,
        type(pd.NaT): lambda nat: None,

        # Integers
        np.int64: lambda x: int(x),

        # Floats
        np.float64: lambda x: float(x),
    }
    # SQLite type -> Python type conversion is split between SQLite3 and pandas
    # (for ease and performance)
    SQLITE3_CONVERTERS: dict[str, Callable] = {
        # Leave IP addresses as is, we will handle it ourselves later
        "IPADDR": lambda ip: ip,
        # Just bytes -> str for timestamps (Pandas will handle the rest)
        "TIMESTAMP": lambda ts: ts.decode() if isinstance(ts, bytes) else ts,
    }
    PANDAS_DTYPE_MAP: dict[type, str] = {
        bool:   'boolean',
        int:    'Int64',
        float:  'Float64',
        str:    'string',
    }

    def __init__(
        self,
        db: "SqliteDatabase",
        table_name: str,
        schema: dict[str, Type[Any]],
        qualifiers: dict[str, str] | None = None,
        table_constraints: list[str] | None = None,
        indices: list[list[str]] | None = None,
    ):
        self.conn = db.conn
        self.table_name = table_name
        self.schema = schema

        # Inherit logger and worker from the database
        self.logger = db.logger
        self._worker = db._worker  # None if not offloaded

        # Inherit write buffering settings from the database
        self._write_buffering = db._write_buffering
        self._write_buf_flush_interval_sec = db._write_buf_flush_interval_sec
        self._write_buf_row_threshold = db._write_buf_row_threshold
        self._writer_exec = db._writer_exec
        self._writer_conn = db._writer_conn
        self._writer_buf: list[pd.DataFrame] = []
        self._writer_kwargs: Dict[str, Any] = {}
        self._writer_rows_since_flush = 0
        self._writer_last_flush = time.time()
        self._writer_lock = threading.Lock()

        def _normalize(text: str):
            return " ".join(text.split()).lower().strip()

        self.qualifiers = qualifiers or {}
        self.qualifiers = {
            col_name: _normalize(qualifier_sql)
            for col_name, qualifier_sql in self.qualifiers.items()
        }
        self.table_constraints = [
            _normalize(tc) for tc in (table_constraints or [])
        ]
        self.indices = indices or []

        if self._worker is None:
            if self.conn is None:
                raise ValueError("conn cannot be None when not using a worker")
            self._create_verify_table()
        else:
            if self.conn is not None:
                raise ValueError("conn must be None when using a worker")
            self.logger.info(
                f"Registered proxy table '{self.table_name}' (backed by worker process)"
            )

    def _create_verify_table(self):
        # Build column definitions
        cols_def: list[str] = []
        for col_name, py_type in self.schema.items():
            # Convert Python type to SQLite type
            sql_type = self.PYTHON_TO_SQLITE.get(py_type)
            if sql_type is None:
                raise TypeError(f"Unsupported type in schema: {py_type}")

            # Validate qualifier syntax by attempting to create a temp table
            qualifier_sql = self.qualifiers.get(col_name, "").strip()
            if qualifier_sql:
                uq = qualifier_sql.upper()
                if not any(uq.startswith(pref) for pref in self.ALLOWED_QUALIFIERS):
                    raise ValueError(
                        f"Invalid qualifier syntax for column '{col_name}': '{qualifier_sql}'"
                    )
            try:
                test_stmt = f"""
                    CREATE TEMP TABLE __test__ ({col_name} {sql_type} {qualifier_sql});
                """
                self.conn.execute(test_stmt)
                self.conn.execute("DROP TABLE IF EXISTS __test__;")
            except sqlite3.OperationalError as e:
                raise ValueError(
                    f"Invalid qualifier syntax for column '{col_name}': {qualifier_sql}, "
                    f"SQLite error: {e}"
                )
            col_def = f"{col_name} {sql_type} {qualifier_sql}".strip()
            cols_def.append(col_def)

        # Add any table-level constraints
        cols_def += self.table_constraints

        # Create table and indices
        try:
            with self.conn:
                ddl = f"CREATE TABLE IF NOT EXISTS {self.table_name} ({', '.join(cols_def)});"
                self.conn.execute(ddl)

                # Create indices
                for idx_cols in self.indices:
                    idx_name = f"idx_{self.table_name}_{'_'.join(idx_cols)}"
                    cols_list = ", ".join(idx_cols)
                    self.conn.execute(
                        f"CREATE INDEX IF NOT EXISTS {idx_name} ON {self.table_name} ({cols_list});"
                    )

            self.logger.info(
                f"Successfully executed create table query: {ddl}"
            )
            self.logger.info(
                f"Successfully created indices {self.indices} for table {self.table_name}"
            )
        except sqlite3.DatabaseError as e:
            raise RuntimeError(
                f"Error while creating table or indices for '{self.table_name}': {e}"
            ) from e

        # Validate existing schema: columns and types
        info = self.conn.execute(
            f"PRAGMA table_info({self.table_name});"
        ).fetchall()
        existing_cols = {row[1]: row[2].upper() for row in info}
        for col_name, py_type in self.schema.items():
            expected = self.PYTHON_TO_SQLITE[py_type]
            actual = existing_cols.get(col_name)
            if actual is None or not actual.startswith(expected):
                raise ValueError(
                    f"Column '{col_name}' type mismatch: expected '{expected}', got '{actual}'"
                )

        # Validate constraints and qualifiers
        # NOTE: This is a simple check and may not cover all cases
        ddl_info = self.conn.execute(
            f"SELECT sql FROM sqlite_master WHERE type='table' AND name=?;",
            (self.table_name,),
        ).fetchone()
        if ddl_info:
            table_sql = ddl_info[0].upper()

            # Validate table-level constraints
            for tc in self.table_constraints:
                if tc.upper() not in table_sql:
                    raise ValueError(f"Missing table constraint in DDL: {tc}")

            # Validate column-level qualifiers
            for col, qualifier_sql in self.qualifiers.items():
                qual = qualifier_sql.strip().upper()
                if qual and qual not in table_sql:
                    raise ValueError(
                        f"Missing qualifier '{qualifier_sql}' for column '{col}' in DDL"
                    )

        # Validate indices
        idx_list = self.conn.execute(
            f"PRAGMA index_list({self.table_name});"
        ).fetchall()
        existing_idxs = {row[1] for row in idx_list}
        for idx_cols in self.indices:
            idx_name = f"idx_{self.table_name}_{'_'.join(idx_cols)}"
            if idx_name not in existing_idxs:
                raise ValueError(f"Missing index: {idx_name}")

        self.logger.info(
            f"Table '{self.table_name}' schema verified successfully."
        )
        self.logger.debug(f"Table constraints: {self.table_constraints}")
        self.logger.debug(f"Qualifiers: {self.qualifiers}")
        self.logger.debug(f"Indices: {self.indices}")

    def cast_df_types_schema(self, df: pd.DataFrame):
        """
        Cast DataFrame columns to match the table schema types.

        Args:
            df (pd.DataFrame):
                DataFrame to cast.

        Returns:
            pd.DataFrame:
                DataFrame with columns cast to match the table schema types.
        """

        for col, typ in self.schema.items():
            if col not in df.columns:
                continue

            # PANDAS_DTYPE_MAP maps some common types
            if typ in self.PANDAS_DTYPE_MAP:
                df[col] = df[col].astype(self.PANDAS_DTYPE_MAP[typ])

            # Handle certain specific types
            elif typ is np.datetime64:
                df[col] = pd.to_datetime(df[col], errors="coerce")
            elif typ is IPv4Address or typ is IPv6Address:
                df[col] = df[col].map(
                    lambda x: try_convert_ip(x) if pd.notna(x) else pd.NA
                )
            elif typ is bytes:
                df[col] = df[col].map(
                    lambda x: x if pd.notna(x) else pd.NA
                )

            # Fallback: try a direct astype(typ), but ignore failures
            else:
                try:
                    df[col] = df[col].astype(typ)
                except Exception:
                    pass

        return df

    def _flush_writer_buffer(self, force: bool = False):
        if not self._write_buffering:
            self.logger.warning(
                "Attempted to flush writer buffer, but write buffering is disabled."
            )
            return

        if self._worker is not None:
            # Worker handles its own buffering
            return

        with self._writer_lock:
            over_rows = self._writer_rows_since_flush >= self._write_buf_row_threshold
            over_time = (
                time.time() - self._writer_last_flush
            ) >= self._write_buf_flush_interval_sec
            need_flush = force or over_rows or over_time
            if not need_flush:
                return

            dfs_to_merge = [
                df for df in self._writer_buf
                if df is not None and not df.empty and df.notna().any().any()
            ]

            if dfs_to_merge:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=FutureWarning)
                    df_merged = pd.concat(dfs_to_merge, ignore_index=True)
                kwargs = self._writer_kwargs or {}

            self._writer_buf = []
            self._writer_kwargs = {}
            self._writer_rows_since_flush = 0
            self._writer_last_flush = time.time()

            if not dfs_to_merge:
                # Nothing to flush
                return

        self.logger.info(
            f"Flushing {len(df_merged)} buffered rows "
            f"(force={force}, over_rows={over_rows}, over_time={over_time}) "
            f"to table '{self.table_name}'."
        )

        kwargs["_flush_call"] = True
        if self._writer_exec is not None:
            self._writer_exec.submit(
                self.insert_df, df_merged, **kwargs
            ).result()
        else:
            # Fallback in case executor is somehow missing
            self.insert_df(df_merged, **kwargs)

    def insert_df(
        self,
        df: pd.DataFrame,
        if_exists: str = "abort",
        cast_columns_to_schema: bool = True,
        *,
        wait_for_worker: bool = False,
        force_flush: bool = False,
        _flush_call: bool = False,  # internal
    ):
        """
        Insert a pandas DataFrame into the table, converting types as needed.

        Args:
            df (pd.DataFrame):
                DataFrame to insert into the table.

            if_exists (str):
                What to do if the rows being inserted would cause a conflict.

                - `fail`: On conflict, raise an error but keep changes made so far.
                - `replace`: On conflict, replace the existing row with the new row.
                - `abort`: On conflict, raise an error and roll back all changes made so far.
                - `ignore`: On conflict, skip the new row.

            cast_columns_to_schema (bool):
                Whether to cast DataFrame columns to match the table schema types.
                Default is True, which will attempt to convert DataFrame types to match the schema.

            wait_for_worker (bool):
                If using a worker process, whether to block until the insert is complete.
                Default is False, which will enqueue the insert and return immediately.

            force_flush (bool):
                If write buffering is enabled, whether to force a flush of the buffer after this insert.
                Default is False.
        """
        if df is None or df.empty or not df.notna().any().any():
            self.logger.info(
                f"DataFrame is empty or None, nothing to insert into '{self.table_name}'."
            )
            return

        if self._worker is not None:
            kwargs = {
                "if_exists": if_exists,
                "cast_columns_to_schema": cast_columns_to_schema,
                "force_flush": force_flush,
            }
            self._worker.insert_df(
                self.table_name, df, block=wait_for_worker, **kwargs
            )
            self.logger.debug(
                f"Inserted {len(df)} rows into table '{self.table_name}' "
                f"via worker with wait_for_worker={wait_for_worker}."
            )
            return

        # Once we are here, we are NOT using a worker
        if self._write_buffering and not _flush_call:
            # We are being called from the main thread.

            # If the call options differ from the current buffer, flush first.
            if self._writer_kwargs and (
                self._writer_kwargs["if_exists"] != if_exists or
                self._writer_kwargs["cast_columns_to_schema"] != cast_columns_to_schema
            ):
                self._flush_writer_buffer(force=True)

            # Buffer the DataFrame and flush if needed.
            with self._writer_lock:
                self._writer_buf.append(df)
                self._writer_rows_since_flush += len(df)
                self._writer_kwargs = {
                    "if_exists": if_exists,
                    "cast_columns_to_schema": cast_columns_to_schema,
                }
            self._flush_writer_buffer(force=force_flush)
            return

        # Once we are here, we are actually inserting into the DB
        start_time = time.perf_counter()

        # Map if_exists to SQLite conflict clauses
        if_exists_map = {
            "fail": "INSERT OR FAIL",
            "replace": "INSERT OR REPLACE",
            "abort": "INSERT",
            "ignore": "INSERT OR IGNORE",
        }
        if_exists = if_exists.lower()
        if if_exists not in if_exists_map:
            raise ValueError(
                f"if_exists='{if_exists}' not one of {', '.join(if_exists_map.keys())}"
            )
        prefix = if_exists_map[if_exists]

        # Build the INSERT statement
        cols = list(self.schema.keys())
        col_list = ", ".join(cols)
        placeholders = ", ".join("?" for _ in cols)
        stmt = (
            f"{prefix} INTO {self.table_name} "
            f"({col_list}) VALUES ({placeholders})"
        )

        # Reorder DataFrame columns to match schema
        df = df.reindex(columns=cols)

        # Cast DataFrame types to match schema if needed
        if cast_columns_to_schema:
            df = self.cast_df_types_schema(df)

        # Use generator to reduce memory footprint
        def _gen_rows():
            yield from df.itertuples(index=False, name=None)

        # Insert with conversion context
        write_conn = self._writer_conn if _flush_call and self._writer_conn else self.conn
        with write_conn:
            write_conn.executemany(stmt, _gen_rows())

        self.logger.info(
            f"Inserted {len(df)} rows into table '{self.table_name}' "
            f"in {time.perf_counter() - start_time:.2f} seconds."
        )

    def query_all(self):
        """
        Query every row/column in the table and return a DataFrame.
        """
        if self._worker is not None:
            return self._worker.query_all(self.table_name)

        cols = ", ".join(self.schema.keys())
        sql = f"SELECT {cols} FROM {self.table_name};"
        return self.query(sql)

    def query(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
        flush_before_query: bool = True,
    ) -> pd.DataFrame:
        """
        Execute a raw SQL query and return results as a DataFrame.

        Args:
            sql (str):
                The SQL query to execute.

            params:
                Parameters to pass to the SQL query.

            flush_before_query (bool):
                If write buffering is enabled, whether to flush the write buffer
                before executing the query.
                This ensures that the query sees the most up-to-date data.
                Default is True.

        Returns:
            df (pd.DataFrame):
                A single DataFrame with the results.
        """
        if self._worker is not None:
            return self._worker.query(
                self.table_name, sql,
                params=params, flush_before_query=flush_before_query,
            )

        if self._write_buffering and flush_before_query:
            self._flush_writer_buffer(force=True)

        start_time = time.perf_counter()

        # We need to somehow identify the requested columns.
        # Here, we briefly execute the query and then close the cursor to get the result schema.
        cur = self.conn.execute(sql, params)
        query_cols = [desc[0] for desc in cur.description]
        cur.close()

        # Identify columns which need to be parsed as dates
        parse_dates = [
            col_name for col_name, py_type in self.schema.items()
            if col_name in query_cols and self.PYTHON_TO_SQLITE[py_type] == "TIMESTAMP"
        ]

        # Identify columns which need to be converted to pandas dtypes
        dtype = {
            col_name: self.PANDAS_DTYPE_MAP[py_type]
            for col_name, py_type in self.schema.items()
            if col_name in query_cols and py_type in self.PANDAS_DTYPE_MAP
        }

        df = pd.read_sql_query(
            sql,
            self.conn,
            params=params,
            parse_dates=parse_dates,
            dtype=dtype,
        )

        # Post-process IP addresses if needed
        if ip_cols := [
            col_name for col_name, py_type in self.schema.items()
            if col_name in query_cols and self.PYTHON_TO_SQLITE[py_type] == "IPADDR"
        ]:
            raw_ips = pd.unique(
                pd.concat([df[col] for col in ip_cols], ignore_index=True)
            )

            # Build a mapping from raw IPs to converted IPAddress objects (or leave as is)
            mapping = {}
            for raw_ip in raw_ips:
                mapping[raw_ip] = try_convert_ip(raw_ip)

            # Apply the mapping to each IP column
            for col in ip_cols:
                df[col] = df[col].map(mapping)

        self.logger.info(
            f"Executed query: {sql} with params: {params}, returned {len(df)} rows "
            f"in {time.perf_counter() - start_time:.2f} seconds."
        )

        return df


def _register_sqlite3_conversions():
    global _sqlite3_conversions_registered, _sqlite3_global_lock

    with _sqlite3_global_lock:
        if _sqlite3_conversions_registered:
            # Only need to register once per process
            return
        # Adapters (Python -> SQLite)
        for py_type, adapter in SqliteTable.SQLITE3_ADAPTERS.items():
            sqlite3.register_adapter(py_type, adapter)
        # Converters (SQLite -> Python)
        for sql_type, converter in SqliteTable.SQLITE3_CONVERTERS.items():
            sqlite3.register_converter(sql_type, converter)
        _sqlite3_conversions_registered = True


class SqliteDatabase:
    """
    A class to manage a SQLite database connection.
    This class allows registering tables with a defined schema, including qualifiers, constraints, and indices.

    Args:
        db_path (str | Path):
            Path to the SQLite database file. If the file does not exist, it will be created.

        wal (bool):
            Whether to use Write-Ahead Logging mode for the database. Default is True.

        uri (bool):
            If True, `db_path` is treated as a URI. Default is False.

        cache_kb (int):
            Size of the SQLite page cache in kilobytes.
            Default is 256,000 KB (256 MB). Minimum is 2,000 KB (2 MB).

        log_helper (LogHelper | None):
            Optional LogHelper for logging messages. If None, no logging will be performed.

        offload_to_worker (bool):
            Whether to offload database operations to a separate worker process.
            This can help avoid blocking the main thread during long-running operations.
            Default is False.

        write_buffering (bool):
            Whether to enable write buffering for insert operations.
            When enabled, insert operations are buffered and written to the database
            in batches, which can improve performance for high-frequency inserts.
            Default is False.

        write_buf_flush_interval_sec (float):
            If write buffering is enabled, the interval in seconds at which to flush
            the write buffer to the database.
            Default is 30.0 seconds.
            Minimum is 1.0 second.

        write_buf_row_threshold (int):
            If write buffering is enabled, the number of rows in the each table's buffer
            that will trigger a flush to the database.
            Default is 1,000 rows.

        **kwargs:
            Additional keyword arguments to pass to `sqlite3.connect()`.
    """

    CACHE_KB_MIN = 2_000
    CACHE_KB_DEFAULT = 256_000
    WRITE_BUF_FLUSH_INTERVAL_SEC_MIN = 1.0
    WRITER_STOP_TIMEOUT_SEC = 2.0
    WRITER_TICK_INTERVAL_SEC = WRITER_STOP_TIMEOUT_SEC / 2
    WRITER_TICK_INTERVAL_SEC_MIN = 0.1

    def __init__(
        self,
        db_path: str | Path,
        wal: bool = True,
        uri: bool = False,
        cache_kb: int = CACHE_KB_DEFAULT,
        *,
        log_helper: Optional[LogHelper] = None,
        offload_to_worker: bool = False,
        write_buffering: bool = False,
        write_buf_flush_interval_sec: float = 30.0,
        write_buf_row_threshold: int = 1_000,
        **kwargs
    ):
        self.path = Path(db_path).resolve()
        self.wal = wal
        self.uri = uri
        self.cache_kb = max(cache_kb, self.CACHE_KB_MIN)
        self.log_helper = log_helper
        self.logger = get_logger_from_helper(self.log_helper)
        self._init_kwargs = kwargs
        self.tables: dict[str, SqliteTable] = {}
        self.conn: Optional[sqlite3.Connection] = None

        # Offloading
        self._worker: Optional[SqliteWorkerHelper] = None
        self._offload_to_worker = offload_to_worker
        self._is_worker = kwargs.pop("is_worker", False)
        if self._is_worker:
            self._offload_to_worker = False  # Do not offload from a worker

        # If not offloading, register conversions (if not already done)
        if not self._offload_to_worker:
            _register_sqlite3_conversions()

        # Buffering
        self._write_buffering = write_buffering
        self._write_buf_flush_interval_sec = max(
            self.WRITE_BUF_FLUSH_INTERVAL_SEC_MIN, write_buf_flush_interval_sec
        )
        self._write_buf_row_threshold = write_buf_row_threshold
        self._writer_exec: Optional[ThreadPoolExecutor] = None
        self._writer_conn: Optional[sqlite3.Connection] = None
        self._writer_ticker: Optional[threading.Thread] = None
        self._writer_last_flush: float = time.time()
        self._writer_stop: threading.Event = threading.Event()

        # Offload to worker process if requested
        if self._offload_to_worker:
            db_init_kwargs = {
                "db_path": str(self.path),
                "wal": wal,
                "uri": uri,
                "cache_kb": cache_kb,
                "log_helper": log_helper,
                "offload_to_worker": False,  # Do not offload further
                "is_worker": True,
                "write_buffering": write_buffering,
                "write_buf_flush_interval_sec": write_buf_flush_interval_sec,
                "write_buf_row_threshold": write_buf_row_threshold,
                **kwargs,
            }
            self._worker = SqliteWorkerHelper(db_init_kwargs)
            self._worker.start()
            self.logger.info(
                f"Connected to SQLite database at {db_path} via worker process"
            )
            return

        # From here on, we are not offloading to a worker

        # Set up buffering if enabled
        if self._write_buffering:
            self._start_writer()

        # Set up connection
        self.conn = self._open_conn()
        self.logger.info(
            f"Connected to SQLite database at {db_path} directly"
        )

    def _open_conn(self):
        conn = sqlite3.connect(
            self.path,
            uri=self.uri,
            detect_types=sqlite3.PARSE_DECLTYPES,
            **self._init_kwargs
        )
        conn.execute(f"PRAGMA cache_size=-{self.cache_kb};")
        if self.wal:
            conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _start_writer(self):
        self._writer_exec = ThreadPoolExecutor(
            max_workers=1, # Single writer because SQLite complains otherwise
            thread_name_prefix=f"{self.__class__.__name__}-writer"
        )
        self._writer_conn = self._writer_exec.submit(
            self._open_conn
        ).result()
        self._writer_stop.clear()
        self._writer_ticker = threading.Thread(
            target=self._writer_tick_loop,
            name=f"{self.__class__.__name__}-writer-ticker",
            daemon=True,
        )
        self._writer_ticker.start()
        self.logger.info("Started SQLite writer thread")

    def _writer_tick_loop(self):
        effective_sleep = max(
            self.WRITER_TICK_INTERVAL_SEC_MIN,
            min(
                self.WRITER_TICK_INTERVAL_SEC,
                self._write_buf_flush_interval_sec / 2,
            )
        )
        while not self._writer_stop.is_set():
            time.sleep(effective_sleep)
            if (time.time() - self._writer_last_flush) < self._write_buf_flush_interval_sec:
                continue
            for table in list(self.tables.values()):
                table._flush_writer_buffer()
            self._writer_last_flush = time.time()

    def _stop_writer(self):
        for table in self.tables.values():
            try:
                table._flush_writer_buffer(force=True)
            except Exception as e:
                self.logger.error(
                    f"Error flushing writer buffer for table '{table.table_name}': {e}"
                )

        try:
            self._writer_stop.set()
            if self._writer_ticker and self._writer_ticker.is_alive():
                self._writer_ticker.join(timeout=self.WRITER_STOP_TIMEOUT_SEC)
        except Exception as e:
            self.logger.error(f"Error stopping writer ticker thread: {e}")

        if self._writer_exec:
            try:
                self._writer_exec.submit(
                    self._writer_conn.close
                ).result(timeout=self.WRITER_STOP_TIMEOUT_SEC)
            except Exception as e:
                self.logger.error(f"Error closing writer connection: {e}")
            self._writer_exec.shutdown(wait=True)

        self._writer_exec = None
        self._writer_conn = None
        self._writer_ticker = None

    def register_table(
        self,
        table_name: str,
        schema: dict[str, Type[Any]],
        qualifiers: dict[str, str] | None = None,
        table_constraints: list[str] | None = None,
        indices: list[list[str]] | None = None
    ):
        """
        Register a table with the database, creating it if it does not already exist.

        Args:
            table_name (str):
                Name of the table to register.

            schema (dict[str, Type[Any]]):
                Dictionary mapping column names to Python types.

            qualifiers (dict[str, str] | None):
                Optional dictionary mapping column names to SQLite qualifiers (e.g., "NOT NULL").

            table_constraints (list[str] | None):
                Optional list of table-level constraints (e.g., "PRIMARY KEY").

            indices (list[list[str]] | None):
                Optional list of lists, where each inner list contains column names for an index.

        Returns:
            table (SqliteTable):
                An instance of `SqliteTable` representing the registered table.
        """

        if table_name in self.tables:
            return self.tables[table_name]

        if self._offload_to_worker:
            if self._worker is None:
                raise RuntimeError("Worker process not initialized.")
            self._worker.register_table(
                table_def={
                    "table_name": table_name,
                    "schema": schema,
                    "qualifiers": qualifiers,
                    "table_constraints": table_constraints,
                    "indices": indices,
                }
            )

        table = SqliteTable(
            self,
            table_name,
            schema,
            qualifiers=qualifiers,
            table_constraints=table_constraints,
            indices=indices,
        )
        self.tables[table_name] = table

        self.logger.info(
            f"Registered table '{table_name}' with schema: {schema}"
        )

        return table

    def close(self):
        """
        Close the database connection.
        """

        if self._write_buffering and not self._offload_to_worker:
            self._stop_writer()

        if self._offload_to_worker and self._worker:
            self.logger.info(
                f"Closing SQLite database worker for {self.path}"
            )
            self._worker.close()
            self._worker = None
            self.logger.info(
                f"Closed SQLite database worker for {self.path}"
            )

        if self.conn:
            if self.wal:
                # Checkpoint WAL to flush all changes to the main DB
                # Do it here since this is the last connection to close
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            self.conn.close()
            self.conn = None
            self.logger.info(
                f"Closed SQLite database connection at {self.path}"
            )
