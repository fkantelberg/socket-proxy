import asyncio
import ssl
import subprocess
import time
from datetime import datetime
from unittest import mock

import pytest
import pytest_asyncio.plugin
from socket_proxy import base, connection, package, proxy, tunnel, utils

CA_CERT = "pki/ca.pem"
CLIENT_CERT = "pki/client.pem"
CLIENT_KEY = "pki/client.key"
SERVER_CERT = "pki/server.pem"
SERVER_KEY = "pki/server.key"

PORT = pytest_asyncio.plugin._unused_tcp_port()
PORT_DUMMY = pytest_asyncio.plugin._unused_tcp_port()

proc = subprocess.Popen(["./certs.sh", "client"], stdin=subprocess.PIPE)
proc.communicate()
proc = subprocess.Popen(["./certs.sh", "server"], stdin=subprocess.PIPE)
proc.communicate(b"y\n" * 80)


def test_generate_ssl_context():
    server = utils.generate_ssl_context(
        cert=SERVER_CERT, key=SERVER_KEY, ca=CA_CERT, server=True,
    )

    client = utils.generate_ssl_context(
        cert=CLIENT_CERT, key=CLIENT_KEY, ca=CA_CERT, server=False, ciphers="RSA",
    )

    assert all(isinstance(ctx, ssl.SSLContext) for ctx in (client, server))
    assert len(server.get_ciphers()) > len(client.get_ciphers())


@pytest.fixture
async def echo_server(event_loop):
    async def accept(reader, writer):
        data = await reader.read(1024)
        writer.write(data)
        await writer.drain()

        writer.close()
        await writer.wait_closed()

    async def loop(server):
        async with server:
            await server.serve_forever()

    server = await asyncio.start_server(accept, host="", port=PORT_DUMMY)
    event_loop.create_task(loop(server))
    yield server
    server.close()
    await server.wait_closed()


@pytest.fixture
async def server(event_loop):
    server = proxy.ProxyServer(
        host="", port=PORT, cert=SERVER_CERT, key=SERVER_KEY, ca=CA_CERT,
    )
    tunnel.Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def client(event_loop):
    client = tunnel.TunnelClient(
        host="localhost",
        port=PORT,
        dst_host="localhost",
        dst_port=PORT_DUMMY,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
    )
    tunnel.Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(client.loop())
    await asyncio.sleep(0.1)
    yield client
    await client.stop()
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_connection_wrong_token():
    conn = connection.Connection(None, None)
    with pytest.raises(base.InvalidPackage):
        await conn.tun_data(b"", b"abc")


@pytest.mark.asyncio
async def test_close_exception():
    def raiseAssert(*args, **kwargs):
        raise AssertionError()

    conn = connection.Connection(None, None)
    conn.reader = conn.writer = mock.MagicMock()
    conn.writer.close = raiseAssert
    await conn.close()


@pytest.mark.asyncio
async def test_tunnel_with_dummy(echo_server, server, client):
    async def connect_and_send(ip, port, text):
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(text)
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return data

    # End to end test with an echo server
    await asyncio.sleep(0.1)
    for ip_type, port in client.addresses:
        if ip_type == base.TransportType.IPv4:
            assert await connect_and_send("127.0.0.1", port, b"abc") == b"abc"
        elif ip_type == base.TransportType.IPv6:
            assert await connect_and_send("::1", port, b"abc") == b"abc"

    # Close the echo server
    echo_server.close()
    await echo_server.wait_closed()

    await asyncio.sleep(0.1)

    for ip_type, port in client.addresses:
        if ip_type == base.TransportType.IPv4:
            assert await connect_and_send("127.0.0.1", port, b"abc") == b""
        elif ip_type == base.TransportType.IPv6:
            assert await connect_and_send("::1", port, b"abc") == b""

    await server.stop()
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_proxy_tunnel_limit(server):
    reader = writer = mock.AsyncMock()
    await asyncio.sleep(0.1)

    server.max_tunnels = 1
    server.tunnels = {b"\x00": mock.AsyncMock()}

    await server._accept(reader, writer)
    assert len(server.tunnels) == 1


def test_start_functions():
    server = proxy.ProxyServer("", PORT, None, None, None)
    server.loop = mock.AsyncMock()
    server.start()
    assert server.loop.call_count

    client = tunnel.TunnelClient("", PORT, "", PORT_DUMMY, None)
    client.loop = mock.AsyncMock()
    client.start()
    assert client.loop.call_count


@pytest.mark.asyncio
async def test_tunnel_client_management():
    cli = mock.AsyncMock()
    cli.token = b"\x00" * base.CLIENT_NAME_SIZE
    other = mock.MagicMock()
    other.token = b"\xff" * base.CLIENT_NAME_SIZE

    # Create without clients
    tun = tunnel.Tunnel(max_clients=1)
    assert len(tun.clients) == 0

    # Add client and get back by token
    tun.add(cli)
    assert len(tun.clients) == 1
    assert tun.get(cli.token) == cli

    # Add the client again
    tun.add(cli)
    assert len(tun.clients) == 1

    # Try adding client with maximum reached
    with pytest.raises(base.ReachedClientLimit):
        tun.add(other)

    # Delete the client
    assert tun.pop(cli.token) == cli
    assert len(tun.clients) == 0

    # Close the tunnel with clients
    tun.add(cli)
    await tun.stop()
    assert cli.close.call_count


@pytest.mark.asyncio
async def test_tunnel_timeout():
    tun = tunnel.Tunnel(max_clients=1)
    tun.stop = mock.AsyncMock()
    tun.tunnel = mock.MagicMock()

    tun.tunnel.last_time = time.time()
    tun.idle_timeout = 0
    await tun.idle()
    assert tun.stop.call_count == 0

    tun.tunnel.last_time -= 10
    await tun.idle()
    assert tun.stop.call_count == 0

    tun.idle_timeout = 5
    await tun.idle()
    assert tun.stop.call_count


@pytest.mark.asyncio
async def test_tunnel_client():
    async def raiseAssert(*args, **kwargs):
        raise AssertionError()

    cli = mock.AsyncMock()
    cli.token = b"\x00" * base.CLIENT_NAME_SIZE
    cli.read.return_value = None

    client = tunnel.TunnelClient("", PORT, "", PORT_DUMMY, None)
    client._disconnect_client = mock.AsyncMock()
    client.add(cli)
    client.tunnel = mock.AsyncMock()
    client.running = True

    # Try connect with existing client
    pkg = package.ClientInitPackage("::1", PORT_DUMMY, cli.token)
    await client._connect_client(pkg)
    assert len(client.clients) == 1

    # Close connection while client still running
    cli.reader = asyncio.StreamReader()
    cli.reader.feed_eof()
    await client._client_loop(cli)
    assert client.tunnel.tun_write.call_count

    # Exception during writing and closing of client
    client.running = True
    cli.reader = asyncio.StreamReader()
    cli.read.return_value = b"abc"
    client.tunnel.tun_write = client.tunnel.tun_data = raiseAssert
    await client._client_loop(cli)

    # Invalid package on the tunnel
    client.tunnel.tun_read = mock.AsyncMock()
    client.tunnel.tun_read.return_value = None
    await client._serve()
    assert client.tunnel.tun_read.call_count


@pytest.mark.asyncio
async def test_tunnel_server():
    def raiseAssert(*args, **kwargs):
        raise AssertionError()

    reader = writer = mock.AsyncMock()
    reader.feed_eof = mock.MagicMock()
    writer.close = mock.MagicMock()
    writer.get_extra_info = mock.MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", PORT)

    server = tunnel.TunnelServer(reader, writer, max_connects=1)

    # Test connection bans
    server.add = raiseAssert
    assert len(server.connections) == 0
    with pytest.raises(AssertionError):
        await server._client_accept(reader, writer)
    assert len(server.connections) == 1

    # Try again should cause a ban
    await server._client_accept(reader, writer)
    assert reader.feed_eof.call_count
    assert writer.close.call_count and writer.wait_closed.called

    # Test the cleaning of the bans
    for ban in server.connections.values():
        ban.first = datetime(1970, 1, 1)

    await server.idle()
    assert len(server.connections) == 0

    # Test client data packages
    token = b"\x00" * base.CLIENT_NAME_SIZE
    m = server.clients[token] = mock.AsyncMock()
    m.write = raiseAssert

    tun = mock.AsyncMock()
    server.tunnel.tun_read = tun

    # Send a valid client data package
    tun.return_value = package.ClientDataPackage(b"abc", token)
    with pytest.raises(AssertionError):
        await server._serve()

    # Send a client data package with invalid token
    tun.return_value = package.ClientDataPackage(b"abc", b"\xff")
    await server._serve()

    # Test a blocked port with impossible range
    server.ports = (5000, 4000)
    server.server = None
    server.tunnel.tun_read.return_value = package.ConnectPackage()
    await server._serve()
    assert server.server is None
