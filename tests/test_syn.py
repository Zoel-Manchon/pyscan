from pyscan.domain.models import PortState
from pyscan.domain.syn import classify


def test_syn_ack_is_open():
    assert classify(0x12) is PortState.OPEN          # SYN+ACK


def test_rst_ack_is_closed():
    assert classify(0x14) is PortState.CLOSED         # RST+ACK


def test_bare_rst_is_closed():
    assert classify(0x04) is PortState.CLOSED


def test_no_response_is_filtered():
    assert classify(None) is PortState.FILTERED


def test_icmp_unreachable_is_filtered():
    assert classify(None, icmp_unreachable=True) is PortState.FILTERED


def test_unexpected_flags_are_filtered():
    assert classify(0x10) is PortState.FILTERED       # lone ACK
