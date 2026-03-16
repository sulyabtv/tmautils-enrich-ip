# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Yejin Cho

from pathlib import Path
import pandas as pd
import warnings
from ipaddress import IPv4Address, IPv6Address, ip_network

from tmautils.core import IOHelper
from ._sqlite_storage import SqliteDatabase, SqliteTable
from ._sqlite_helpers import SqliteLpmTrieHelper


class IpInfoCarrierUtil:
    """
    Utility class for interacting with the ipinfo.io carrier dataset.

    Args:
        ipinfo_carrier_dir (Path):
            Directory where the ipinfo carrier dataset is stored.

        date (str | None):
            Date of the dataset to use, in 'YYYY-MM-DD' format.
            If None, the latest available dataset will be used.

        working_root (Path | None):
            Base directory for data files.
            If None, the current working directory will be used.

        data_dir (Path | None):
            Deprecated alias for `working_root`.

        **kwargs (dict):
            Additional arguments for IOHelper.
            See the IOHelper class for more details.
    """

    CSV_CHUNK_SIZE = 50_000

    def __init__(
        self,
        ipinfo_carrier_dir: Path,
        date: str | None = None,
        working_root: Path | None = None,
        data_dir: Path | None = None,
        **kwargs,
    ):
        working_root = IOHelper.handle_working_root_data_dir(
            working_root, data_dir
        )

        kwargs.setdefault("raw_dir_symlink_to", ipinfo_carrier_dir)
        self.io_helper = IOHelper.init_with_dirs(
            self.__class__.__name__,
            dirs={"raw", "processed", "logs"},
            working_root=working_root,
            **kwargs,
        )

        # Raw and processed paths
        raw_path = self._locate_csv(date)
        self.db_path = self.io_helper.processed / f"{raw_path.stem}.sqlite3"
        is_initialized = self.db_path.exists()

        # Initialize SqliteDatabase and register the table
        self.db = SqliteDatabase(
            self.db_path,
            log_helper=self.io_helper.log_helper,
        )
        self.ipinfo_carrier_table: SqliteTable = self.db.register_table(
            "ipinfo_carrier",
            schema={
                "version":          int,
                "prefix_length":    int,
                "network_start":    IPv6Address,
                "network_end":      IPv6Address,

                "name":             str,
                "country":          str,
                "mcc":              int,
                "mnc":              int
            },
            qualifiers={
                "version": "NOT NULL",
                "prefix_length": "NOT NULL",
                "network_start": "NOT NULL",
                "network_end": "NOT NULL",
            },
            table_constraints=[
                "PRIMARY KEY (version, network_start, prefix_length)"
            ],
            indices=[["version", "network_start", "network_end"]],
        )
        if not is_initialized:
            self._populate_table(raw_path)

        # Use SqliteLpmTrieHelper for fast lookups
        self.lpm_helper = SqliteLpmTrieHelper(
            self.db.path,
            self.ipinfo_carrier_table,
            log_helper=self.io_helper.log_helper,
        )

        self.io_helper.logger.info(
            f"Initialized IpInfoCarrierUtil with date: {date if date else 'latest'}"
        )

    def _locate_csv(self, date: str | None = None):
        if date is not None:
            # Verify that the date is in the ISO format 'YYYY-MM-DD'
            try:
                pd.to_datetime(date, format="%Y-%m-%d", errors="raise")
            except ValueError:
                self.io_helper.logger.error(
                    f"Invalid date format: {date}. Expected 'YYYY-MM-DD'."
                )
                raise

            # Verify that the corresponding file exists
            raw_path = self.io_helper.raw / f"ipinfo_carrier.{date}.csv"
            if not raw_path.exists():
                self.io_helper.logger.error(
                    f"Data file for date {date} does not exist: {raw_path}"
                )
                raise FileNotFoundError(
                    f"Data file for date {date} not found.")
        else:
            # List available data files
            data_files = list(self.io_helper.raw.glob("ipinfo_carrier.*.csv"))
            if not data_files:
                self.io_helper.logger.error(
                    "No ipinfo carrier data files found in the raw directory."
                )
                raise FileNotFoundError("No ipinfo carrier data files found.")

            # Sort by date and take the most recent one
            data_files.sort(key=lambda x: x.stem.split('.')[-1], reverse=True)
            raw_path = data_files[0]

        return raw_path

    def _populate_table(self, raw_path: Path):
        # Stream the CSV in chunks, compute numeric columns, insert
        self.io_helper.logger.info(
            f"Populating SQLite database at {self.db_path}"
        )
        chunker = pd.read_csv(
            raw_path,
            dtype={
                "name":    str,
                "country": str,
                "mcc":     int,
                "mnc":     int,
            },
            chunksize=self.CSV_CHUNK_SIZE,
        )
        for df_chunk in chunker:
            df_chunk: pd.DataFrame

            net_objs = df_chunk.pop("network").map(lambda x: ip_network(x))
            df_chunk["version"] = net_objs.map(lambda n: n.version)
            df_chunk["prefix_length"] = net_objs.map(lambda n: n.prefixlen)
            df_chunk["network_start"] = net_objs.map(
                lambda n: n.network_address
            )
            df_chunk["network_end"] = net_objs.map(
                lambda n: n.broadcast_address
            )

            # Write to the SQLite database
            self.ipinfo_carrier_table.insert_df(df_chunk)

        self.io_helper.logger.info(
            "Created and populated SQLite database at {self.db_path}."
        )

    def is_ip_carrier(
        self,
        ip: IPv4Address | IPv6Address | str
    ) -> bool:
        ret = self.lookup(ip)
        if not ret.empty:
            return True
        else:
            return False

    def is_carrier(self, ip: str) -> bool:
        warnings.warn(
            "is_carrier() is deprecated; use is_ip_carrier() instead",
            category=DeprecationWarning,
            stacklevel=2  # point the warning at the caller’s line
        )

        return self.is_ip_carrier(ip)

    def lookup(
            self,
            ip: IPv4Address | IPv6Address | str
    ) -> pd.Series:
        """
        Lookup the carrier info for a given IP.

        Args:
            addr (IPv4Address | IPv6Address | str):
                The IP address to look up.

        Returns:
            ret (pd.Series | None):
                A pandas Series containing the privacy information for the given IP address,
                or None if the address is not found in the dataset.
                In original dataset, the columns are:
                    - network, name, country, mcc, mnc
        """

        return self.lpm_helper.lookup(ip)

    def get_carrier_by_ip(self, ip: str) -> dict | None:
        warnings.warn(
            "get_carrier_by_ip() is deprecated; use lookup() instead",
            category=DeprecationWarning,
            stacklevel=2  # point the warning at the caller’s line
        )
        self.lookup(ip)
