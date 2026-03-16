# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Yejin Cho

from ipaddress import IPv6Address, ip_network
from pathlib import Path
import pandas as pd

from tmautils.core import IOHelper, IPAddress
from ._sqlite_storage import SqliteDatabase, SqliteTable
from ._sqlite_helpers import SqliteLpmTrieHelper


class ChromePrefetchUtil:
    """
    Utility class to check if an IP address belongs to Chrome Prefetch Proxy.

    This class downloads the Chrome Prefetch Proxy geofeed data, processes it,
    and provides methods to look up IP addresses to determine if they are part of
    the Chrome Prefetch Proxy network.

    Args:
        working_root (Path | None):
            Base directory where the namespace directory will be created.
            If None, the current working directory will be used.

        data_dir (Path | None):
            Deprecated alias for `working_root`.

        **kwargs (dict):
            Additional arguments for IOHelper.
            See the IOHelper class for more details.
    """

    def __init__(
        self,
        working_root: Path | None = None,
        data_dir: Path | None = None,
        **kwargs,
    ):
        working_root = IOHelper.handle_working_root_data_dir(
            working_root, data_dir
        )
        self.io_helper = IOHelper.init_with_dirs(
            self.__class__.__name__,
            dirs={"raw", "processed", "logs"},
            working_root=working_root,
            **kwargs,
        )

        data_url = f"https://www.gstatic.com/chrome/prefetchproxy/prefetch_proxy_geofeed"
        saved_data_file = self.io_helper.raw / data_url.split("/")[-1]

        # Check if the files exist, if not, download them
        if not saved_data_file.exists():
            import requests

            try:
                self.io_helper.logger.info(
                    f"Downloading Chrome Prefetch Proxy file from {data_url} to {saved_data_file}"
                )
                r = requests.get(data_url, timeout=5)
            except requests.exceptions.Timeout:
                self.io_helper.logger.error(
                    f"Could not download Chrome Prefetch Proxy file from {data_url}, cannot proceed"
                )
                raise
            else:
                saved_data_file.write_text(r.text)

        # Load raw data file & Parse the file
        self.df = self._load_geofeed_from_file(saved_data_file)

        self.io_helper.logger.info(
            f"Loaded Chrome Prefetch Proxy dataset from {saved_data_file}"
        )

        # building tree
        self.db_path = self.io_helper.processed.joinpath(
            f"{saved_data_file.stem}.sqlite3"
        )
        is_initialized = self.db_path.exists()

        # Initialize SqliteDatabase and register the table
        self.db = SqliteDatabase(
            self.db_path,
            log_helper=self.io_helper.log_helper,
        )
        self.ipinfo_carrier_table: SqliteTable = self.db.register_table(
            "chrome_prefetch",
            schema={
                "version": int,
                "prefix_length": int,
                "network_start": IPv6Address,
                "network_end": IPv6Address,

                "country": str,
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
            self._populate_table(self.df)

        # Use SqliteLpmTrieHelper for fast lookups
        self.lpm_helper = SqliteLpmTrieHelper(
            self.db.path,
            self.ipinfo_carrier_table,
            log_helper=self.io_helper.log_helper,
        )

        self.io_helper.logger.info(
            f"Initialized IpInfoCarrierUtil "
            f"with top-level directory: {self.io_helper.top_level_dir}"
        )

    def _populate_table(self, df: pd.DataFrame):
        self.io_helper.logger.info(
            f"Populating SQLite database at {self.db_path}"
        )

        net_objs = df.pop("network").map(lambda x: ip_network(x))
        df["version"] = net_objs.map(lambda n: n.version)
        df["prefix_length"] = net_objs.map(lambda n: n.prefixlen)
        df["network_start"] = net_objs.map(lambda n: n.network_address)
        df["network_end"] = net_objs.map(lambda n: n.broadcast_address)

        # Write to the SQLite database
        self.ipinfo_carrier_table.insert_df(df)

        self.io_helper.logger.info(
            "Created and populated SQLite database at {self.db_path}."
        )

    def _load_geofeed_from_file(self, path: Path) -> pd.DataFrame:
        with path.open("r", encoding="utf-8") as f:
            lines = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]

        records = [line.split(",") for line in lines]
        df = pd.DataFrame(
            records,
            columns=['network', 'country', 'field1', 'field2', 'field3']
        )

        # if empty, drop the columns
        empty_cols = [col for col in ['field1', 'field2', 'field3']
                      if df[col].str.strip().eq('').all()]
        df = df.drop(columns=empty_cols)

        return df

    def lookup(
        self,
        ip: IPAddress | str
    ) -> pd.Series:
        """
        Lookup the carrier info for a given IP.

        Args:
            addr (IPv4Address | IPv6Address | str):
                The IP address to look up.

        Returns:
            ret (pd.Series):
                A pandas Series containing the lookup result.
                If the IP is not found, the Series will be empty.
        """
        return self.lpm_helper.lookup(ip)
