# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Yejin Cho

import textwrap
from pathlib import Path
import pytest

from tmautils.enrich_ip.vpn import IpInfoPrivacyUtil

FAKE_CSV = textwrap.dedent("""\
    network,hosting,proxy,tor,relay,vpn,service
    1.0.0.0/24,true,false,false,false,false,
    1.0.1.0/24,true,false,false,false,true,ExampleVPN
    10.0.0.0/8,false,true,false,false,false,ProxyService
    192.168.0.0/16,false,false,true,false,false,TorExit
    2001:db8::/32,true,false,false,false,true,IPv6VPN
""")


@pytest.fixture()
def ipinfo_util(tmp_path: Path):
    data_dir = tmp_path / "ipinfo_data"
    data_dir.mkdir()
    csv_file = data_dir / "ipinfo_privacy.2025-01-01.csv"
    csv_file.write_text(FAKE_CSV)

    return IpInfoPrivacyUtil(
        ipinfo_privacy_dir=data_dir,
        date="2025-01-01",
        working_root=tmp_path / "work",
    )


class TestLookup:
    def test_lookup_match(self, ipinfo_util: IpInfoPrivacyUtil):
        result = ipinfo_util.lookup("1.0.1.50")
        assert result["vpn"] is True
        assert result["hosting"] is True
        assert result["service"] == "ExampleVPN"

    def test_lookup_no_match(self, ipinfo_util: IpInfoPrivacyUtil):
        result = ipinfo_util.lookup("8.8.8.8")
        assert result["vpn"] is None
        assert result["service"] is None

    def test_lookup_ipv6(self, ipinfo_util: IpInfoPrivacyUtil):
        result = ipinfo_util.lookup("2001:db8::1")
        assert result["vpn"] is True
        assert result["service"] == "IPv6VPN"

    def test_lookup_lpm_longest_prefix(self, ipinfo_util: IpInfoPrivacyUtil):
        """10.x.x.x matches 10.0.0.0/8 (proxy), not a shorter prefix."""
        result = ipinfo_util.lookup("10.1.2.3")
        assert result["proxy"] is True
        assert result["vpn"] is False


class TestIsIpVpn:
    def test_vpn_ip(self, ipinfo_util: IpInfoPrivacyUtil):
        is_vpn, service = ipinfo_util.is_ip_vpn("1.0.1.100")
        assert is_vpn is True
        assert service == "ExampleVPN"

    def test_non_vpn_ip(self, ipinfo_util: IpInfoPrivacyUtil):
        is_vpn, service = ipinfo_util.is_ip_vpn("1.0.0.50")
        assert is_vpn is False
        assert service is None

    def test_no_match(self, ipinfo_util: IpInfoPrivacyUtil):
        is_vpn, service = ipinfo_util.is_ip_vpn("172.16.0.1")
        assert is_vpn is False
        assert service is None

    def test_vpn_without_service(self, ipinfo_util: IpInfoPrivacyUtil):
        """1.0.0.0/24 has vpn=false, so not a VPN even though hosting=true."""
        is_vpn, service = ipinfo_util.is_ip_vpn("1.0.0.1")
        assert is_vpn is False
        assert service is None

    def test_ipv6_vpn(self, ipinfo_util: IpInfoPrivacyUtil):
        is_vpn, service = ipinfo_util.is_ip_vpn("2001:db8::abcd")
        assert is_vpn is True
        assert service == "IPv6VPN"
