import pytest

from pyscan.domain.rate import Pacer


def test_first_slot_is_immediate():
    p = Pacer(rate=10, start=0.0)
    assert p.reserve(0.0) == 0.0


def test_back_to_back_spaced_by_interval():
    p = Pacer(rate=10, start=0.0)  # interval = 0.1s
    p.reserve(0.0)
    assert round(p.reserve(0.0), 6) == 0.1
    assert round(p.reserve(0.0), 6) == 0.2


def test_interval_matches_rate():
    p = Pacer(rate=4, start=0.0)  # interval = 0.25s
    p.reserve(0.0)
    assert round(p.reserve(0.0), 6) == 0.25


def test_idle_gap_does_not_bank_a_burst():
    p = Pacer(rate=10, start=0.0)
    p.reserve(0.0)               # next slot at 0.1
    assert p.reserve(5.0) == 0.0  # long past it -> resets to now, no catch-up


def test_rate_must_be_positive():
    with pytest.raises(ValueError):
        Pacer(rate=0)
    with pytest.raises(ValueError):
        Pacer(rate=-5)
