import pytest

from pyscan.domain.top_ports import TOP_PORTS, top_ports


def test_returns_n_ports():
    assert len(top_ports(5)) == 5


def test_most_common_first():
    assert top_ports(1) == [80]  # port 80 is #1 in the list


def test_no_duplicates():
    full = top_ports(len(TOP_PORTS))
    assert len(full) == len(set(full))


def test_n_larger_than_list_returns_all():
    assert top_ports(10_000) == list(TOP_PORTS)


def test_zero_or_negative_rejected():
    with pytest.raises(ValueError):
        top_ports(0)
