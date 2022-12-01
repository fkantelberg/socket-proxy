import asyncio
import ssl
import subprocess
import time
from datetime import datetime
from unittest import mock

import pytest
from aiohttp import ClientSession, web

from socket_proxy import Tunnel, TunnelClient, base, connection, package, proxy, utils

CA_CERT = "pki/ca.pem"
CLIENT_CERT = "pki/client.pem"
CLIENT_KEY = "pki/client.key"
SERVER_CERT = "pki/server.pem"
SERVER_KEY = "pki/server.key"
CRL = "pki/crl.pem"

TCP_PORT = utils.get_unused_port(5000, 10000)
TCP_PORT_DUMMY = utils.get_unused_port(5000, 10000)

with subprocess.Popen(["./certs.sh", "client"], stdin=subprocess.PIPE) as proc:
    proc.communicate()
with subprocess.Popen(["./certs.sh", "server"], stdin=subprocess.PIPE) as proc:
    proc.communicate(b"y\n" * 80)


# pylint: disable=W0613


def raiseAssertAsync(*args, **kwargs):
    raise AssertionError()


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
    await asyncio.sleep(0.1)
    yield server
    server.close()
    await server.wait_closed()
    await asyncio.sleep(0.1)


@pytest.fixture
async def server(event_loop):
    server = proxy.ProxyServer(
        host="",
        port=TCP_PORT,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
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
    base.config.http_domain = "example.org"
    base.config.http_listen = "127.0.0.1", utils.get_unused_port(5000, 10000)

    server = proxy.ProxyServer(
        host="",
        port=TCP_PORT,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
        protocols=[base.ProtocolType.HTTP],
    )
    Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def api_server(event_loop):
    base.config.api = True
    base.config.api_listen = "127.0.0.1", utils.get_unused_port(5000, 10000)
    base.config.http_listen = "127.0.0.1", utils.get_unused_port(5000, 10000)

    server = proxy.ProxyServer(
        host="",
        port=TCP_PORT,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
        protocols=[base.ProtocolType.TCP, base.ProtocolType.HTTP],
    )
    Tunnel._interval = mock.AsyncMock()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@pytest.fixture
async def api_client(event_loop):
    base.config.api = True
    base.config.api_listen = "127.0.0.1", utils.get_unused_port(5000, 10000)
    base.config.http_listen = "127.0.0.1", utils.get_unused_port(5000, 10000)

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
    async def idle(*_args, **_kwargs):
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
async def test_authenticated_tunnel(server):
    server.authentication = True
    token = server.generate_token()

    client = TunnelClient(
        host="localhost",
        port=TCP_PORT,
        dst_host="localhost",
        dst_port=TCP_PORT_DUMMY,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
        auth_token=token,
    )
    client._interval = mock.AsyncMock()
    asyncio.create_task(client.loop())
    await asyncio.sleep(0.1)
    assert client.addr
    await client.stop()
    await asyncio.sleep(0.1)

    client.addr = []
    client.auth_token = "invalid"
    asyncio.create_task(client.loop())
    await asyncio.sleep(0.1)
    assert not client.addr

    client.auth_token = False
    asyncio.create_task(client.loop())
    await asyncio.sleep(0.1)
    assert not client.addr

    req_mock = mock.AsyncMock(path="/api/token")
    response = await server._api_index(req_mock)
    assert response.status == 200
    await asyncio.sleep(0.1)

    server.authentication = False
    with pytest.raises(web.HTTPNotFound):
        await server._api_index(req_mock)
    await asyncio.sleep(0.1)

    resp = await server._api_handle(("invalid",), req_mock)
    assert resp is None
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_proxy_token_cleanup(server):
    server.tokens["old-token"] = datetime(1970, 1, 1)
    await server.idle()
    assert "old-token" not in server.tokens
    assert not server.tokens

    server.authentication = True
    await server.idle()
    assert server.tokens


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
    assert client.addr
    for ip_type, port in client.addr:
        if ip_type == base.InternetType.IPv4:
            assert await connect_and_send("127.0.0.1", port, b"abc") == b"abc"
        elif ip_type == base.InternetType.IPv6:
            assert await connect_and_send("::1", port, b"abc") == b"abc"

    # Close the echo server
    echo_server.close()
    await echo_server.wait_closed()

    await asyncio.sleep(0.1)

    for ip_type, port in client.addr:
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
            "127.0.0.1",
            http_server.http_port,
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
    reader = writer = mock.AsyncMock(feed_eof=mock.MagicMock(), close=mock.MagicMock())
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
    base.config.max_clients = 1
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
    base.config.max_clients = 1
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


@pytest.mark.asyncio
async def test_tunnel_ping(server, client):
    # No ping when disabled
    client.ping_enabled = False
    await client.idle()
    await asyncio.sleep(0.1)
    assert client.last_ping is None
    assert client.last_pong is None

    # A ping is executed
    client.ping_enabled = True
    await client.idle()
    await asyncio.sleep(0.1)
    assert client.last_ping is not None
    assert client.last_pong is not None

    # Server sends pong and last_pong updates
    pkg = package.PingPackage(client.last_ping + 1000)
    client.last_ping = client.last_pong = None
    await server.tunnels[client.uuid].tunnel.tun_write(pkg)
    await asyncio.sleep(0.1)
    assert client._check_alive() is True
    assert client.last_pong is not None

    # Stop the tunnel if time out
    client.last_ping, client.last_pong = 0, 2 * base.INTERVAL_TIME
    client.stop = mock.AsyncMock()
    await client.idle()
    assert client.stop.called

    # Check the alive
    client.last_ping, client.last_pong = 0, 0.5 * base.INTERVAL_TIME
    assert client._check_alive() is True

    client.last_ping = client.last_pong = None
    assert client._check_alive() is True

    # Ping too high
    client.last_ping, client.last_pong = 0, 100000
    assert client._check_alive() is False


@pytest.mark.asyncio
async def test_api_client(echo_server, api_server, api_client, http_client):
    async def connect_and_send(ip, port):
        # Open a connection to get a client
        reader, writer = await asyncio.open_connection(ip, port)
        await asyncio.sleep(0.1)
        writer.write(b"hello")
        await writer.drain()

        # Get the client UUID
        async with session.get("/", headers=headers) as response:
            data = await response.json()
            clients = data["clients"]
            assert clients
            cuuid = list(clients)[0]

        # Delete the client using the client API
        async with session.delete(f"/{cuuid}", headers=headers) as response:
            assert response.status == 200

        # Client already deleted
        async with session.delete(f"/{cuuid}", headers=headers) as response:
            assert response.status == 404

        await reader.read(1024)

    # Testing of the client API
    async with ClientSession(f"http://localhost:{api_client.api_port}") as session:
        async with session.get("/") as response:
            assert response.status == 200
            assert await response.json() == api_client.get_state_dict()

        async with session.get("/invalid") as response:
            assert response.status == 404

        async with session.get("/tcp") as response:
            assert response.status == 200
            assert await response.json() == api_client.get_state_dict()["tcp"]

        # Activate API token
        api_client.api_token = "Bearer abcd"
        headers = {"Authorization": "Bearer abcd"}
        async with session.get("/") as response:
            assert response.status == 403

        async with session.delete("/") as response:
            assert response.status == 403

        async with session.get("/", headers=headers) as response:
            assert response.status == 200

        async with session.delete("/", headers=headers) as response:
            assert response.status == 404

        async with session.delete("/invalid", headers=headers) as response:
            assert response.status == 404

        for ip_type, port in api_client.addr:
            if ip_type == base.InternetType.IPv4:
                await connect_and_send("127.0.0.1", port)
            elif ip_type == base.InternetType.IPv6:
                await connect_and_send("::1", port)


@pytest.mark.asyncio
async def test_api_server(echo_server, api_server, api_client, http_client):
    async def connect_and_send(ip, port):
        # Open a connection to get a client
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b"hello")
        await writer.drain()

        # Get the client UUID
        async with session.get("/", headers=headers) as response:
            data = await response.json()
            clients = data["tunnels"][tuuid]["clients"]
            assert clients
            cuuid = list(clients)[0]

        # Delete the client using the server API
        async with session.delete(f"/{tuuid}/{cuuid}", headers=headers) as response:
            assert response.status == 200

        # Client already deleted
        async with session.delete(f"/{tuuid}/{cuuid}", headers=headers) as response:
            assert response.status == 404

        await reader.read(1024)

    # Testing of the server API
    async with ClientSession(f"http://localhost:{api_server.api_port}") as session:
        async with session.get("/") as response:
            assert response.status == 200
            data = await response.json()
            assert data == api_server.get_state_dict()
            assert len(data["tunnels"]) == 2

        async with session.get("/tcp") as response:
            assert response.status == 200
            assert await response.json() == api_server.get_state_dict()["tcp"]

        async with session.get("/invalid") as response:
            assert response.status == 404

        async with session.get("/api/token") as response:
            assert response.status == 404

        # Activate API token
        api_server.api_token = "Bearer abcd"
        headers = {"Authorization": "Bearer abcd"}
        tuuid = api_client.uuid
        async with session.get("/") as response:
            assert response.status == 403

        async with session.delete("/") as response:
            assert response.status == 403

        async with session.get("/", headers=headers) as response:
            assert response.status == 200

        for ip_type, port in api_client.addr:
            if ip_type == base.InternetType.IPv4:
                await connect_and_send("127.0.0.1", port)
            elif ip_type == base.InternetType.IPv6:
                await connect_and_send("::1", port)

        # Disconnect the tunnel using the API
        async with session.delete(f"/{tuuid}", headers=headers) as response:
            assert response.status == 200

        # Tunnel already disconnected
        async with session.delete(f"/{tuuid}", headers=headers) as response:
            assert response.status == 404
