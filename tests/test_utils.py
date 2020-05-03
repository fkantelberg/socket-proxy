import argparse
import ipaddress
import socket

import pytest
from socket_proxy import base, utils


def test_transport_type():
    cls = base.TransportType
    assert cls.from_ip("127.0.0.1") == cls.IPv4
    assert cls.from_ip("::1") == cls.IPv6

    with pytest.raises(ipaddress.AddressValueError):
        cls.from_ip(12)


def test_ban():
    ban = base.Ban()
    assert ban.hits == 0


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


def test_parse_address():
    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1:80/test")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("127.0.0.1")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address(":80")

    with pytest.raises(argparse.ArgumentTypeError):
        utils.parse_address("localhost:123456")

    assert utils.parse_address("127.0.0.1:80") == ("127.0.0.1", 80)
    assert utils.parse_address("[::]:80") == ("::", 80)
    assert utils.parse_address(":80", host="::") == ("::", 80)
    assert utils.parse_address("[::]", port=80) == ("::", 80)
    assert utils.parse_address("", host="::", port=80) == ("::", 80)


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
    for fail in [":", "0", "0:6000", "5000:90000", "6000:5000"]:
        with pytest.raises(argparse.ArgumentTypeError):
            utils.valid_ports(fail)

    assert utils.valid_ports("5000:6000") == (5000, 6000)
