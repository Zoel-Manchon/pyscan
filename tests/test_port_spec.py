import pytest

from pyscan.domain.port_spec import parse_port_spec


def test_single_ports():
    assert parse_port_spec("22,80,443") == [22, 80, 443]


def test_range():
    assert parse_port_spec("1-5") == [1, 2, 3, 4, 5]


def test_mixed_and_dedup():
    assert parse_port_spec("80,1-3,80") == [1, 2, 3, 80]


def test_reversed_range_is_normalised():
    assert parse_port_spec("5-1") == [1, 2, 3, 4, 5]


def test_whitespace_tolerated():
    assert parse_port_spec(" 22 , 80 ") == [22, 80]


def test_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_port_spec("70000")


def test_rejects_garbage():
    with pytest.raises(ValueError):
        parse_port_spec("abc")
