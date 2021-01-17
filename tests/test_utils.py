import argparse
import ipaddress
import socket
from tempfile import NamedTemporaryFile
from unittest import mock

import pytest
from socket_proxy import base, utils
from socket_proxy.config import OptionDefault, config, to_bool


def test_transport_type():
    cls = base.InternetType
    assert cls.from_ip("127.0.0.1") == cls.IPv4
    assert cls.from_ip("::1") == cls.IPv6

    with pytest.raises(ipaddress.AddressValueError):
        cls.from_ip(12)


def test_ban():
    ban = base.Ban()
    assert ban.hits == 0


def test_to_bool():
    assert to_bool("1") is True
    assert to_bool("on") is True
    assert to_bool("t") is True
    assert to_bool("true") is True
    assert to_bool("True") is True
    assert to_bool("TRUE") is True
    assert to_bool("False") is False


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


def test_config():
    with NamedTemporaryFile() as fp:
        fp.write(b"[server]\nban-time=15\nports=7000:9000\n[client]\nban-time=20\n")
        fp.seek(0, 0)

        assert not config.load("missing", fp.name)

        assert "ban-time" in config
        assert config.get("missing") is None
        assert config["ban-time"] == OptionDefault["ban-time"]
        assert config.load("server", fp.name)
        assert config["ban-time"] == 15
        assert config["ports"] == (7000, 9000)
        config.load("client", fp.name)
        assert config["ban-time"] == 20

        args = mock.Mock()
        args.ban_time = 45
        config.load_arguments(args)
        assert config["ban-time"] == 45


def test_config_protocols():
    config["no-tcp"] = 0
    config["no-http"] = 0
    config["http-domain"] = "example.org"
    assert config.protocols == {base.ProtocolType.TCP, base.ProtocolType.HTTP}
    config["no-tcp"] = 1
    assert config.protocols == {base.ProtocolType.HTTP}
    config["no-http"] = 1
    assert config.protocols == set()
    config["no-http"] = 0
    config["http-domain"] = None
    assert config.protocols == set()


def test_configure_logging():
    utils.configure_logging(None, "INFO")
    utils.configure_logging("test.log", "DEBUG")


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
