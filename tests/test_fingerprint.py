from pyscan.domain.fingerprint import identify


def test_openssh_banner():
    info = identify("SSH-2.0-OpenSSH_9.6 Ubuntu", 22)
    assert info.service == "ssh"
    assert info.product == "OpenSSH"
    assert info.version == "9.6"


def test_nginx_server_header():
    banner = "HTTP/1.0 200 OK Server: nginx/1.24.0 Date: Mon"
    info = identify(banner, 80)
    assert info.service == "http"
    assert info.product == "nginx"
    assert info.version == "1.24.0"


def test_apache_without_version():
    info = identify("HTTP/1.1 200 OK Server: Apache Content-Type: text/html", 8080)
    assert info.service == "http"
    assert info.product == "Apache"


def test_generic_server_header_falls_through():
    info = identify("HTTP/1.0 200 OK Server: CustomThing/2.1", 80)
    assert info.service == "http"
    assert info.product == "CustomThing/2.1"


def test_no_banner_uses_port_guess():
    info = identify(None, 22)
    assert info.service == "ssh"
    assert info.product is None
    assert info.version is None


def test_unknown_port_no_banner_is_empty():
    info = identify(None, 49152)
    assert info.service is None


def test_unmatched_banner_falls_back_to_port():
    info = identify("some totally unrecognised greeting", 3306)
    assert info.service == "mysql"  # from well-known port, since banner didn't match
