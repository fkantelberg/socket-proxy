import asyncio
import ipaddress
import ssl
import subprocess
import time
from datetime import datetime
from io import StringIO
from unittest import mock

import pytest
import pytest_asyncio.plugin
from socket_proxy import (
    Tunnel,
    TunnelClient,
    TunnelServer,
    base,
    config,
    connection,
    package,
    proxy,
    utils,
)

CA_CERT = "pki/ca.pem"
CLIENT_CERT = "pki/client.pem"
CLIENT_KEY = "pki/client.key"
SERVER_CERT = "pki/server.pem"
SERVER_KEY = "pki/server.key"

TCP_PORT = pytest_asyncio.plugin._unused_tcp_port()
TCP_PORT_DUMMY = pytest_asyncio.plugin._unused_tcp_port()

proc = subprocess.Popen(["./certs.sh", "client"], stdin=subprocess.PIPE)
proc.communicate()
proc = subprocess.Popen(["./certs.sh", "server"], stdin=subprocess.PIPE)
proc.communicate(b"y\n" * 80)


def raiseAssert(*args, **kwargs):
    raise AssertionError()


def raiseAssertAsync(*args, **kwargs):
    raise AssertionError()


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

    server = await asyncio.start_server(accept, host="", port=TCP_PORT_DUMMY)
    event_loop.create_task(loop(server))
    yield server
    server.close()
    await server.wait_closed()


@pytest.fixture
async def server(event_loop):
    server = proxy.ProxyServer(
        host="", port=TCP_PORT, cert=SERVER_CERT, key=SERVER_KEY, ca=CA_CERT,
    )
    Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def client(event_loop):
    client = TunnelClient(
        host="localhost",
        port=TCP_PORT,
        dst_host="localhost",
        dst_port=TCP_PORT_DUMMY,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
    )
    Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(client.loop())
    await asyncio.sleep(0.1)
    yield client
    await client.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def http_server(event_loop):
    server = proxy.ProxyServer(
        host="",
        port=TCP_PORT,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        http_domain="example.org",
        protocols=[base.ProtocolType.HTTP],
    )
    Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def http_client(event_loop):
    client = TunnelClient(
        host="localhost",
        port=TCP_PORT,
        dst_host="localhost",
        dst_port=TCP_PORT_DUMMY,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
        protocol=base.ProtocolType.HTTP,
    )
    Tunnel._interval = mock.AsyncMock()
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
async def test_tunnel_idle():
    async def idle(*args, **kwargs):
        if not hasattr(idle, "counter"):
            idle.counter = True
        else:
            raise AssertionError()

    tun = Tunnel()
    tun.idle = idle
    base.INTERVAL_TIME = 0.01

    with pytest.raises(AssertionError):
        await tun._interval()


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
    assert client.addresses
    for ip_type, port in client.addresses:
        if ip_type == base.InternetType.IPv4:
            assert await connect_and_send("127.0.0.1", port, b"abc") == b"abc"
        elif ip_type == base.InternetType.IPv6:
            assert await connect_and_send("::1", port, b"abc") == b"abc"

    # Write information into a file
    with StringIO() as fp:
        config["store-information"] = fp
        client.store_information()
        assert fp.tell()
        config["store-information"] = None

    # Close the echo server
    echo_server.close()
    await echo_server.wait_closed()

    await asyncio.sleep(0.1)

    for ip_type, port in client.addresses:
        if ip_type == base.InternetType.IPv4:
            assert await connect_and_send("127.0.0.1", port, b"abc") == b""
        elif ip_type == base.InternetType.IPv6:
            assert await connect_and_send("::1", port, b"abc") == b""

    await server.stop()
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_http_tunnel_with_dummy(echo_server, http_server, http_client):
    async def connect_and_send(text):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", base.DEFAULT_HTTP_PORT,
        )
        writer.write(text)
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return data

    # End to end test with an echo server
    await asyncio.sleep(0.1)

    request = b"abc\r\n\r\n"
    assert await connect_and_send(request) == b""
    request = b"GET / HTTP/1.1\r\n\r\n"
    assert await connect_and_send(request) == b"HTTP/1.1 404 Not Found\r\n\r\n"
    request = b"GET / HTTP/1.1\r\nHost: test.example.org\r\n\r\n"
    assert await connect_and_send(request) == b"HTTP/1.1 404 Not Found\r\n\r\n"

    assert http_server.tunnels
    token = list(http_server.tunnels)[0]
    request = b"GET / HTTP/1.1\r\nHost: %s.example.org\r\n\r\n" % token.encode()
    assert await connect_and_send(request) == request

    http_server.tunnels[token].protocol = base.ProtocolType.TCP
    assert await connect_and_send(request) == b"HTTP/1.1 404 Not Found\r\n\r\n"

    # Close the echo server
    echo_server.close()
    await echo_server.wait_closed()

    await http_server.stop()
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
    server = proxy.ProxyServer("", TCP_PORT, None, None, None)
    server.loop = mock.AsyncMock()
    server.start()
    assert server.loop.call_count

    client = TunnelClient("", TCP_PORT, "", TCP_PORT_DUMMY, None)
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
    config["max-clients"] = 1
    tun = Tunnel()
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
    config["max-clients"] = 1
    tun = Tunnel()
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
    cli = mock.AsyncMock()
    cli.token = b"\x00" * base.CLIENT_NAME_SIZE
    cli.read.return_value = None

    client = TunnelClient("", TCP_PORT, "", TCP_PORT_DUMMY, None)
    client._disconnect_client = mock.AsyncMock()
    client.add(cli)
    client.tunnel = mock.AsyncMock()
    client.running = True

    # Try connect with existing client
    pkg = package.ClientInitPackage("::1", TCP_PORT_DUMMY, cli.token)
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
    client.tunnel.tun_write = client.tunnel.tun_data = raiseAssertAsync
    await client._client_loop(cli)

    # Invalid package on the tunnel
    client.tunnel.tun_read = mock.AsyncMock()
    client.tunnel.tun_read.return_value = None
    assert await client._handle() is False
    assert client.tunnel.tun_read.call_count

    client.tunnel.tun_read.return_value = package.Package()
    assert await client._handle() is False


def init_test_server():
    reader = writer = mock.AsyncMock()
    reader.feed_eof = mock.MagicMock()
    writer.close = mock.MagicMock()
    writer.get_extra_info = mock.MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", TCP_PORT)

    config["max-connects"] = 1
    server = TunnelServer(reader, writer)
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
