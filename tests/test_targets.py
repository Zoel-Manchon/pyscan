import pytest

from pyscan.domain.targets import expand_targets


def test_single_ip():
    assert expand_targets("192.168.1.5") == ["192.168.1.5"]


def test_hostname_passes_through():
    assert expand_targets("scanme.nmap.org") == ["scanme.nmap.org"]


def test_cidr_24_excludes_network_and_broadcast():
    hosts = expand_targets("192.168.1.0/24")
    assert len(hosts) == 254
    assert "192.168.1.1" in hosts
    assert "192.168.1.254" in hosts
    assert "192.168.1.0" not in hosts
    assert "192.168.1.255" not in hosts


def test_cidr_30():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_range_too_large_raises():
    with pytest.raises(ValueError):
        expand_targets("10.0.0.0/8")
