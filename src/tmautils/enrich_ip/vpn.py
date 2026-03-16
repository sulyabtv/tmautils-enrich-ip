# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Yejin Cho

from typing import Optional
from pathlib import Path
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
import pandas as pd
import requests

from tmautils.core import IOHelper
from ._sqlite_storage import SqliteDatabase, SqliteTable
from ._sqlite_helpers import SqliteLpmTrieHelper


class VpnIpAz0:
    """
        Utility class for interacting with the az0/vpn_ip Github library.

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
    URL_IP = "https://raw.githubusercontent.com/az0/vpn_ip/refs/heads/main/data/output/ip.txt"
    URL_HOSTNAME = "https://raw.githubusercontent.com/az0/vpn_ip/refs/heads/main/data/output/hostname.txt"

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
            dirs={"raw", "logs"},
            working_root=working_root,
            **kwargs,
        )

        self._download_current_file()

        self.io_helper.logger.info("Initialized VpnIPAz0")

    def _download_current_file(self):
        """
        Downloads the latest VPN IP and hostname data from the az0/vpn_ip repository.
        This method retrieves the latest data files and saves them in the raw directory, and create dataframe and return.
        """

        ip_file = self.io_helper.raw / "vpn_ip.txt"
        hostname_file = self.io_helper.raw / "vpn_hostname.txt"

        try:
            self.io_helper.logger.info(
                "Downloading current VPN IP and hostname data..."
            )
            r_ip = requests.get(self.URL_IP, timeout=5)
            r_hostname = requests.get(self.URL_HOSTNAME, timeout=5)
        except requests.exceptions.Timeout:
            self.io_helper.logger.error(
                f"Could not download VPN IP data from {self.URL_IP}, cannot proceed"
            )
            raise
        else:
            ip_file.write_text(r_ip.text)
            hostname_file.write_text(r_hostname.text)

        # Convert results into DataFrames
        self.df_vpn_hostname = pd.read_csv(
            hostname_file,
            header=None,
            comment="#",
            names=["hostname"],
            dtype={'hostname': str},
        )

        self.df_vpn_ip = pd.read_csv(
            ip_file,
            sep=r'\s*#\s*',
            engine='python',
            header=None,
            names=["ip", "hostname"],
            dtype={"ip": str, "hostname": str},
            skip_blank_lines=True,
        )

    def get_hostnames(self):
        """
        Returns a list of hostnames from the az0/vpn_ip dataset.
        """
        return self.df_vpn_hostname

    def get_vpn_ips(self) -> list[tuple[str | IPv4Address | IPv6Address, str]]:
        """
        Returns a list of VPN IPs from the az0/vpn_ip dataset.
        """
        return self.df_vpn_ip

    def is_hostname_vpn(self, hostname: str) -> bool:
        """
        Checks if the given hostname is associated with a VPN IP.

        Args:
            hostname (str): The hostname to check.

        Returns:
            is_vpn (bool): True if the hostname is associated with a VPN IP, False otherwise.
        """

        # Normalize input
        host = hostname.strip().lower()

        # Ensure df exists and has the expected column
        if not hasattr(self, 'df_vpn_hostname') or 'hostname' not in self.df_vpn_hostname:
            return False

        # Build a lowercase set of known VPN hostnames for fast lookup
        vpn_hosts = set(self.df_vpn_hostname['hostname'])

        return host in vpn_hosts

    def is_ip_vpn(self, ip: str | IPv4Address | IPv6Address) -> tuple[bool, Optional[str]]:
        """
        Checks if the given IP address is a VPN IP.

        Args:
            ip (IPv4Address | IPv6Address): The IP address to check.

        Returns:
            (is_vpn, hostname) (tuple[bool, Optional[str]]):
            A tuple where the first element is True if the IP is a VPN IP,
            and the second element is the hostname if available, otherwise None.
        """

        # Convert IP object to string for comparison
        ip_str = str(ip)

        # Filter df_vpn_ip for matching ip
        match = self.df_vpn_ip[self.df_vpn_ip['ip'].astype(str) == ip_str]

        if not match.empty:
            # If found, take the first hostname
            hostname = match.iloc[0]['hostname']
            return True, hostname

        return False, None


class ListsVpnX4BNet:
    """
    Utility class for interacting with the X4BNet/lists_vpn VPN and datacenter lists.

    Downloads and caches the IPv4 prefix lists for both VPN-only and
    combined datacenter+VPN networks, and provides query methods.

    Args:
        working_root (Path | None):
            Base directory where the namespace directory will be created.
            If None, the current working directory will be used.

        data_dir (Path | None):
            Deprecated alias for `working_root`.

        **kwargs:
            Additional arguments for IOHelper.
    """
    URL_VPN_IPV4 = (
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/"
        "main/output/vpn/ipv4.txt"
    )
    URL_DC_IPV4 = (
        "https://raw.githubusercontent.com/X4BNet/lists_vpn/"
        "main/output/datacenter/ipv4.txt"
    )

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
            dirs={"raw", "logs"},
            working_root=working_root,
            **kwargs
        )

        # Download raw files and load into DataFrames
        self._download_lists()

        self.io_helper.logger.info("Initialized ListsVpnX4BNet")

    def _download_lists(self) -> None:
        """
        Download the latest VPN-only and datacenter+VPN IPv4 lists
        into the raw directory.
        Load the downloaded text files into pandas DataFrames.
        Each file is a one-column list of prefixes (CIDRs).
        """
        vpn_v4_file = self.io_helper.raw / "vpn_ipv4.txt"
        dc_v4_file = self.io_helper.raw / "dc_ipv4.txt"

        try:
            self.io_helper.logger.info(
                "Downloading VPN and datacenter IPv4 lists..."
            )
            r_vpn = requests.get(self.URL_VPN_IPV4, timeout=5)
            r_dc = requests.get(self.URL_DC_IPV4, timeout=5)
        except requests.exceptions.Timeout:
            self.io_helper.logger.error(
                f"Could not download VPN IPv4 data from {self.URL_VPN_IPV4}, cannot proceed"
            )
            raise
        else:
            vpn_v4_file.write_text(r_vpn.text)
            dc_v4_file.write_text(r_dc.text)

        self.df_vpn = pd.read_csv(
            vpn_v4_file,
            header=None,
            names=["prefix"],
            dtype={"prefix": str},
            comment="#",
        )

        self.df_dc = pd.read_csv(
            dc_v4_file,
            header=None,
            names=["prefix"],
            dtype={"prefix": str},
            comment="#",
        )

    def get_vpn_ips(self) -> pd.DataFrame:
        """
        Returns:
            pd.DataFrame: DataFrame of VPN-only prefixes (column: prefix).
        """
        return self.df_vpn.copy()

    def get_datacenter_ips(self) -> pd.DataFrame:
        """
        Returns:
            pd.DataFrame: DataFrame of datacenter+VPN prefixes (column: prefix).
        """
        return self.df_dc.copy()

    def is_ip_vpn(
        self,
        ip: str | IPv4Address,
    ) -> tuple[bool, Optional[str]]:
        """
        Checks if the given IPv4 address falls within any VPN-only prefix.

        Args:
            ip (str | IPv4Address):
                The IP address to check.
        Returns:
            (is_vpn, prefix) (tuple(bool, Optional[str])):
                True and matching prefix if VPN; else False, None.
        """
        ip_obj = ip_address(str(ip))
        # Iterate over prefixes
        for pref in self.df_vpn["prefix"]:
            network = ip_network(pref)
            if ip_obj in network:
                return True, pref
        return False, None

    def is_ip_datacenter(
        self,
        ip: str | IPv4Address,
    ) -> tuple[bool, Optional[str]]:
        """
        Checks if the given IPv4 address falls within any datacenter+VPN prefix.

        Args:
            ip (str | IPv4Address): The IP address to check.
        Returns:
            (bool, Optional[str]): True and matching prefix if datacenter/VPN; else False, None.
        """
        ip_obj = ip_address(str(ip))
        for pref in self.df_dc["prefix"]:
            network = ip_network(pref)
            if ip_obj in network:
                return True, pref
        return False, None


class IpInfoPrivacyUtil:
    """
    Utility class for interacting with the ipinfo.io privacy dataset.

    Args:
        ipinfo_privacy_dir (Path):
            Directory where the ipinfo privacy dataset is stored.

        date (str | None):
            Date of the dataset to use, in 'YYYY-MM-DD' format.
            If None, the latest available dataset will be used.

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
        ipinfo_privacy_dir: Path,
        date: str | None = None,
        working_root: Path | None = None,
        data_dir: Path | None = None,
        **kwargs,
    ):
        working_root = IOHelper.handle_working_root_data_dir(
            working_root, data_dir
        )

        kwargs.setdefault("raw_dir_symlink_to", ipinfo_privacy_dir)
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
        self.ipinfo_privacy_table: SqliteTable = self.db.register_table(
            "ipinfo_privacy",
            schema={
                "version":          int,
                "prefix_length":    int,
                "network_start":    IPv6Address,
                "network_end":      IPv6Address,
                "hosting":          bool,
                "proxy":            bool,
                "tor":              bool,
                "relay":            bool,
                "vpn":              bool,
                "service":          str,
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
            self.ipinfo_privacy_table,
            log_helper=self.io_helper.log_helper,
        )

        self.io_helper.logger.info(
            f"Initialized IpInfoPrivacyUtil with date: {date if date else 'latest'} "
            f"and database at {self.db_path}"
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
            raw_path = self.io_helper.raw / f"ipinfo_privacy.{date}.csv"
            if not raw_path.exists():
                self.io_helper.logger.error(
                    f"Data file for date {date} does not exist: {raw_path}"
                )
                raise FileNotFoundError(
                    f"Data file for date {date} not found.")
        else:
            # List available data files
            data_files = list(self.io_helper.raw.glob("ipinfo_privacy.*.csv"))
            if not data_files:
                self.io_helper.logger.error(
                    "No ipinfo privacy data files found in the raw directory."
                )
                raise FileNotFoundError("No ipinfo privacy data files found.")

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
                "hosting": bool,
                "proxy":   bool,
                "tor":     bool,
                "relay":   bool,
                "vpn":     bool,
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
            self.ipinfo_privacy_table.insert_df(df_chunk)

        self.io_helper.logger.info(
            "Created and populated SQLite database at {self.db_path}."
        )

    def lookup(
        self,
        addr: IPv4Address | IPv6Address | str,
    ) -> pd.Series:
        """
        Lookup the privacy information for a given IP address.

        Args:
            addr (IPv4Address | IPv6Address | str):
                The IP address to look up.

        Returns:
            ret (pd.Series | None):
                A pandas Series containing the privacy information for the given IP address,
                or None if the address is not found in the dataset.
                In original dataset, the columns are:
                    - network, hosting, proxy, tor, relay, vpn, service
        """

        return self.lpm_helper.lookup(addr)

    def is_ip_vpn(
        self,
        addr: IPv4Address | IPv6Address | str,
    ) -> tuple[bool, Optional[str]]:
        """
        Check if the given IP address is associated with a VPN.

        Args:
            addr (IPv4Address | IPv6Address | str):
                The IP address to check.

        Returns:
            (is_vpn, service) (tuple[bool, Optional[str]]):
                A tuple where the first element is True if the IP is a VPN,
                and the second element is the service name if available, otherwise None.
        """
        ret = self.lookup(addr)
        if not ret.empty:
            if "vpn" in ret and ret["vpn"]:
                # If 'service' is present, return it
                if "service" in ret and pd.notna(ret["service"]):
                    return True, ret["service"]
                return True, None
        # If not found or not a VPN, return False
        return False, None

    def get_all(self) -> pd.DataFrame:
        return self.ipinfo_privacy_table.query_all()
