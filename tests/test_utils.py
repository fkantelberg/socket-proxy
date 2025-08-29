import argparse
import ipaddress
import logging
import socket
import ssl
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from socket_proxy import base, utils

from .common import CA_CERT, CLIENT_CERT, CLIENT_KEY, CRL, SERVER_CERT, SERVER_KEY


def test_generate_ssl_context():
    server = utils.generate_ssl_context(
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
        server=True,
    )

    client = utils.generate_ssl_context(
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
        server=False,
        ciphers="RSA",
    )

    assert all(isinstance(ctx, ssl.SSLContext) for ctx in (client, server))
    assert len(server.get_ciphers()) != len(client.get_ciphers())


def test_transport_type():
    cls = base.InternetType
    assert cls.from_ip("127.0.0.1") == cls.IPv4
    assert cls.from_ip("::1") == cls.IPv6

    with pytest.raises(ipaddress.AddressValueError):
        cls.from_ip(12)


def test_ban():
    ban = utils.Ban()
    assert ban.hits == 0


def test_protocol_from_string():
    assert base.ProtocolType.from_str("tcp") == base.ProtocolType.TCP
    assert base.ProtocolType.from_str("tcP") == base.ProtocolType.TCP
    assert base.ProtocolType.from_str("TCP") == base.ProtocolType.TCP
    assert base.ProtocolType.from_str("http") == base.ProtocolType.HTTP

    with pytest.raises(ValueError):
        base.ProtocolType.from_str("tcpa")


def test_format_transfer():
    with pytest.raises(ValueError):
        utils.format_transfer(-1)

    assert utils.format_transfer(1), "1"
    assert utils.format_transfer(1 << 10), "1.0 K"
    assert utils.format_transfer(2048), "2.0 K"
    assert utils.format_transfer(4 << 40), "4 T"


def test_config_protocols():
    base.config.no_tcp = 0
    base.config.no_http = 0
    base.config.http_domain = "example.org"
    assert set(utils.protocols()) == {
        base.ProtocolType.TCP,
        base.ProtocolType.HTTP,
        base.ProtocolType.BRIDGE,
    }
    base.config.no_tcp = 1
    assert set(utils.protocols()) == {base.ProtocolType.HTTP, base.ProtocolType.BRIDGE}
    base.config.no_http = 1
    assert set(utils.protocols()) == {base.ProtocolType.BRIDGE}
    base.config.no_bridge = 1
    assert set(utils.protocols()) == set()
    base.config.no_http = 0
    base.config.http_domain = None
    assert set(utils.protocols()) == set()


def test_configure_logging():
    utils.configure_logging(None, "INFO")
    log = logging.getLogger()
    list(map(log.removeHandler, log.handlers))

    utils.configure_logging("test.log", "DEBUG")
    list(map(log.removeHandler, log.handlers))


def test_token():
    a = utils.generate_token()
    assert isinstance(a, bytes)
    assert len(a) == base.CLIENT_NAME_SIZE


def test_merge_settings():
    assert utils.merge_settings(0, 0) == 0
    assert utils.merge_settings(9, 0) == 9
    assert utils.merge_settings(0, 9) == 9
    assert utils.merge_settings(9, 4) == 4
    assert utils.merge_settings(4, 9) == 4


def test_optimize_networks():
    def n(network):
        return ipaddress.ip_network(network)

    a, b, c = map(n, ("127.0.0.0/16", "127.0.0.0/24", "127.0.1.0/24"))
    d, e, f = map(n, ("ff::/32", "fd::/64", "ff::/64"))
    # The result should be unique
    assert utils.optimize_networks(a, a, d, d) == [a, d]

    # The order shouldn't matter
    assert utils.optimize_networks(a, b) == [b]
    assert utils.optimize_networks(b, a) == [b]
    assert utils.optimize_networks(b, c) == [b, c]
    assert utils.optimize_networks(c, b) == [b, c]

    # Try a full example
    assert utils.optimize_networks(a, b, c, d, e, f) == [b, c, e, f]


def test_parse_address():
    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1:80/test")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address(":80")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("[:80")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("example.org")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("example:org")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("localhost:123456")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1,[::1]:80")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1,example.org:80")

    assert utils.parse_address("127.0.0.1:80") == ("127.0.0.1", 80)
    assert utils.parse_address("[::]:80") == ("::", 80)
    assert utils.parse_address(":80", host="::") == ("::", 80)
    assert utils.parse_address("[::]", port=80) == ("::", 80)
    assert utils.parse_address("", host="::", port=80) == ("::", 80)
    assert utils.parse_address("example.org", port=80) == ("example.org", 80)
    assert utils.parse_address("example.org:80") == ("example.org", 80)

    hosts = ["127.0.0.1", "::1"]
    addresses = "127.0.0.1,[::1]:80"
    assert utils.parse_address(addresses, multiple=True), (hosts, 80)


def test_parse_network():
    a, b = "0.0.0.0/0", "::/0"

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_networks(".")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_networks(f"{a}{b}")

    assert len(utils.parse_networks(f"{a},{b}")) == 2


def test_traverse_dict():
    data = {"a": {"b": 42}}
    assert utils.traverse_dict(data) == data
    assert utils.traverse_dict(data, False, "", None) == data
    assert utils.traverse_dict(data, "a") == {"b": 42}
    assert utils.traverse_dict(data, "a", "b") == 42
    with pytest.raises(KeyError):
        utils.traverse_dict(data, "c")


def test_valid_file():
    with pytest.raises(argparse.ArgumentTypeError):
        assert utils.valid_file(__file__ + "a")
    assert utils.valid_file(__file__) == __file__


def test_unused_port():
    assert utils.get_unused_port(5000, 4000) is None
    # Just hope that one port is free
    port = utils.get_unused_port(5000, 65535)
    assert isinstance(port, int)

    # Block a port and check it
    sock = socket.socket()
    sock.bind(("", port))
    _, port = sock.getsockname()
    assert utils.get_unused_port(port, port) is None
    sock.close()


def test_valid_ports():
    for fail in [":", "0", "0:6000", "5000:90000"]:
        with pytest.raises(argparse.ArgumentTypeError):
            utils.valid_ports(fail)

    assert utils.valid_ports("5000:6000") == (5000, 6000)


def test_valid_token():
    with pytest.raises(argparse.ArgumentTypeError):
        utils.valid_token("")

    token = str(uuid4())
    assert utils.valid_token(token) == token


def test_parser():
    parser = utils.ConfigArgumentParser()
    parser.add_argument("pos")
    parser.add_argument("-f-a", "--flag-a")
    parser.add_argument("-s", "--switch", default=False, action="store_true")
    parser.add_argument("--other", "-o", default=True, action="store_false")
    parser.add_argument("-c", action="store_const", const=42)
    mock = parser.parse_args = MagicMock()

    parser.parse_with_config([])
    mock.assert_called_once_with([])
    mock.reset_mock()

    parser.parse_with_config(["--other"], {"unknown": True, "flag_a": 1, "switch": 42})
    mock.assert_called_once_with(["--other", "-f-a", "1", "-s"])
    mock.reset_mock()

    parser.parse_with_config([], {"switch": "true"})
    mock.assert_called_once_with(["-s"])
    mock.reset_mock()

    parser.parse_with_config([], {"other": "0"})
    mock.assert_called_once_with(["--other"])
    mock.reset_mock()

    parser.parse_with_config(["-f-a", "42"], {"flag_a": 43})
    mock.assert_called_once_with(["-f-a", "42"])
    mock.reset_mock()

    parser.parse_with_config(["-c"], {})
    mock.assert_called_once_with(["-c"])
