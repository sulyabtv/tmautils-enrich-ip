# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Sulyab Thottungal Valapu, Yejin Cho

from ipaddress import IPv4Address, IPv6Address, ip_network
from pathlib import Path
import pandas as pd

from tmautils.core import IOHelper, gunzip_file
from ._sqlite_storage import SqliteDatabase, SqliteTable
from ._sqlite_helpers import SqliteLpmTrieHelper


class IPInfoLiteUtil:
    """
    Utility class to interact with the IPinfo Lite dataset.

    Args:
        ipinfo_lite_path (Path):
            Path to the IPinfo Lite CSV file. Can be gzipped (.gz).

        working_root (Path | None):
            Base directory where the namespace directory will be created.
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
        ipinfo_lite_path: Path,
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
        raw_path = self.io_helper.create_symlink(
            self.io_helper.raw, ipinfo_lite_path
        )

        # If the file is compressed, decompress it
        if raw_path.suffix == ".gz":
            raw_path = gunzip_file(
                raw_path,
                delete_gzip=False,
                logger=self.io_helper.logger,
            )

        # Initialize SqliteDatabase and register the table
        self.db_path = self.io_helper.processed / f"{raw_path.stem}.sqlite"
        is_initialized = self.db_path.exists()
        self.db = SqliteDatabase(
            self.db_path,
            log_helper=self.io_helper.log_helper,
        )
        self.ipinfo_lite_table: SqliteTable = self.db.register_table(
            "ipinfo_lite",
            schema={
                "version":          int,
                "prefix_length":    int,
                "network_start":    IPv6Address,
                "network_end":      IPv6Address,
                "country":          str,
                "country_code":     str,
                "continent":        str,
                "continent_code":   str,
                "asn":              str,
                "as_name":          str,
                "as_domain":        str,
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
            self.ipinfo_lite_table,
            log_helper=self.io_helper.log_helper,
        )

        self.io_helper.logger.info(
            f"Initialized IpInfoLiteUtil with raw data from {raw_path}"
        )

    def _populate_table(self, raw_path: Path):
        # Stream the CSV in chunks, compute numeric columns, insert
        self.io_helper.logger.info(
            f"Populating SQLite database at {self.db_path}"
        )
        chunker = pd.read_csv(
            raw_path,
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
            self.ipinfo_lite_table.insert_df(df_chunk)

        self.io_helper.logger.info(
            "Created and populated SQLite database at {self.db_path}."
        )

    def lookup(
        self,
        addr: IPv4Address | IPv6Address | str,
    ):
        """
        Lookup the IPinfo Lite information for a given IP address.

        Args:
            addr (IPv4Address | IPv6Address | str):
                The IP address to look up.

        Returns:
            ret (pd.Series | None):
                A pandas Series containing the privacy information for the given IP address,
                or None if the address is not found in the dataset.
        """

        return self.lpm_helper.lookup(addr)
