import ipaddress
from datetime import datetime
from unittest import mock

import pytest

from socket_proxy import TunnelServer, base, package, utils

TCP_PORT = utils.get_unused_port(5000, 10000)


def raiseAssert(*args, **kwargs):
    raise AssertionError()


def init_test_server():
    reader = writer = mock.AsyncMock()
    reader.feed_eof = mock.MagicMock()
    writer.close = mock.MagicMock()
    writer.get_extra_info = mock.MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", TCP_PORT)

    base.config.max_connects = 1
    server = TunnelServer(reader, writer, event=mock.AsyncMock())
    server.add = raiseAssert
    return server, reader, writer


@pytest.mark.asyncio
async def test_tunnel_server():
    server, reader, writer = init_test_server()

    assert len(server.connections) == 0
    with pytest.raises(AssertionError):
        await server._client_accept(reader, writer)

    assert len(server.connections) == 1
    # Try again should cause a ban
    await server._client_accept(reader, writer)

    # Test connection from different ips
    server.max_connects = 100
    server.networks = [ipaddress.ip_network("127.0.1.0/24")]
    await server._client_accept(reader, writer)

    server.networks = [ipaddress.ip_network("127.0.0.0/24")]
    with pytest.raises(AssertionError):
        await server._client_accept(reader, writer)

    server.networks = []

    assert reader.feed_eof.call_count
    assert writer.close.call_count and writer.wait_closed.called

    # Test the cleaning of the bans
    for ban in server.connections.values():
        ban.first = datetime(1970, 1, 1)

    await server.idle()
    assert len(server.connections) == 0


def init_test_server_tun():
    server = init_test_server()[0]
    token = b"\x00" * base.CLIENT_NAME_SIZE
    m = server.clients[token] = mock.AsyncMock()
    m.write = raiseAssert

    tun = mock.AsyncMock()
    server.tunnel.tun_read = tun
    server.tunnel.write = mock.AsyncMock()
    return server, tun


@pytest.mark.asyncio
async def test_tunnel_server_invalid_token():
    server, tun = init_test_server_tun()
    # Send a client data package with invalid token
    tun.return_value = package.ClientDataPackage(b"abc", b"\xff")
    assert await server._handle() is False


@pytest.mark.asyncio
async def test_tunnel_server_protocols():
    server, tun = init_test_server_tun()
    # Test if the filtering of protocols works
    server.protocols = [base.ProtocolType.TCP]
    tun.return_value = package.ConnectPackage(base.ProtocolType.TCP)
    assert await server._handle() is True

    server.protocols = []
    tun.return_value = package.ConnectPackage(base.ProtocolType.TCP)
    assert await server._handle() is False

    server.protocols = [base.ProtocolType.HTTP]
    tun.return_value = package.ConnectPackage(base.ProtocolType.HTTP)
    assert await server._handle() is True


@pytest.mark.asyncio
async def test_tunnel_server_packages():
    server, tun = init_test_server_tun()
    # Test an invalid package
    tun.return_value = package.Package()
    assert await server._handle() is False

    # Send a valid client data package
    token = b"\x00" * base.CLIENT_NAME_SIZE
    tun.return_value = package.ClientDataPackage(b"abc", token)
    with pytest.raises(AssertionError):
        await server._serve()


@pytest.mark.asyncio
async def test_tunnel_server_blocked_port():
    server, tun = init_test_server_tun()
    # Test a blocked port with impossible range
    server.ports = (5000, 4000)
    server.server = None
    server.protocols = [base.ProtocolType.TCP]
    tun.return_value = package.ConnectPackage(base.ProtocolType.TCP)
    assert await server._handle() is False
