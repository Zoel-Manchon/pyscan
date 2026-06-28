from pyscan.domain.udp_probes import payload_for


def test_dns_probe_is_version_bind():
    p = payload_for(53)
    assert b"version" in p and b"bind" in p
    assert p[12:13] == b"\x07"  # qname length octet for "version"


def test_ntp_probe_is_48_bytes_mode3():
    p = payload_for(123)
    assert len(p) == 48
    assert p[0] == 0x1B


def test_snmp_probe_has_community():
    p = payload_for(161)
    assert p.startswith(b"\x30")
    assert b"public" in p


def test_dnp3_probe_has_start_bytes():
    p = payload_for(20000)
    assert p[:2] == b"\x05\x64"
    assert len(p) == 10  # header(8) + CRC(2)


def test_modbus_udp_probe():
    p = payload_for(502)
    assert p[7:8] == b"\x2b"  # Read Device ID function code in the PDU


def test_unknown_port_default():
    assert payload_for(9999) == b"\x00"
