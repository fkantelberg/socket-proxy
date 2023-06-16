import asyncio
import time
from datetime import datetime
from tempfile import NamedTemporaryFile
from unittest import mock

import pytest

from socket_proxy import Tunnel, TunnelClient, base, connection, package, proxy

from .common import (
    CA_CERT,
    CLIENT_CERT,
    CLIENT_KEY,
    client,
    echo_server,
    http_client,
    http_server,
    raiseAssertAsync,
    server,
    unused_ports,
)

# pylint: disable=W0613


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
async def test_authenticated_tunnel():
    port, dst_port = unused_ports(2)
    async with server(port) as srv:
        srv.authentication = True
        token = srv.generate_token()

        cli = TunnelClient(
            host="localhost",
            port=port,
            dst_host="localhost",
            dst_port=dst_port,
            cert=CLIENT_CERT,
            key=CLIENT_KEY,
            ca=CA_CERT,
            auth_token=token,
        )
        cli._interval = mock.AsyncMock()
        asyncio.create_task(cli.loop())
        await asyncio.sleep(0.1)
        assert cli.addr
        await cli.stop()
        await asyncio.sleep(0.1)

        cli.addr = []
        cli.auth_token = "invalid"
        asyncio.create_task(cli.loop())
        await asyncio.sleep(0.1)
        assert not cli.addr
        await cli.stop()
        await asyncio.sleep(0.1)

        cli.addr = []
        cli.auth_token = srv.generate_token(True)
        base.config.auth_hotp = True
        asyncio.create_task(cli.loop())
        await asyncio.sleep(0.1)
        assert cli.addr
        await cli.stop()
        await asyncio.sleep(0.1)

        cli.addr = []
        cli.auth_token = "invalid"
        asyncio.create_task(cli.loop())
        await asyncio.sleep(0.1)
        assert not cli.addr
        await cli.stop()
        await asyncio.sleep(0.1)

        cli.addr = []
        cli.auth_token = False
        asyncio.create_task(cli.loop())
        await asyncio.sleep(0.1)
        await cli.stop()
        assert not cli.addr


@pytest.mark.asyncio
async def test_server_state_persistent():
    (port,) = unused_ports(1)
    async with server(port) as srv:
        with NamedTemporaryFile("w+") as fp:
            srv.authentication = True
            srv.generate_token()
            srv.generate_token(True)

            srv._save_persisted_state(fp.name)

            fp.seek(0)
            data = srv.tokens[base.AuthType.TOTP]
            srv.tokens[base.AuthType.TOTP] = {}
            srv._load_persisted_state(fp.name)
            assert list(data) == list(srv.tokens[base.AuthType.TOTP])
            assert srv.tokens[base.AuthType.TOTP]


@pytest.mark.asyncio
async def test_proxy_token_cleanup():
    (port,) = unused_ports(1)
    async with server(port) as srv:
        srv.authentication = False
        srv.tokens[base.AuthType.TOTP]["old-token"] = base.AuthToken(
            datetime(1970, 1, 1)
        )
        await srv.idle()
        assert "old-token" not in srv.tokens[base.AuthType.TOTP]
        assert not srv.tokens[base.AuthType.TOTP]

        srv.authentication = True
        await srv.idle()
        assert srv.tokens[base.AuthType.TOTP]


@pytest.mark.asyncio
async def test_close_exception():
    def raiseAssert(*args, **kwargs):
        raise AssertionError()

    conn = connection.Connection(None, None)
    conn.reader = conn.writer = mock.MagicMock()
    conn.writer.close = raiseAssert
    await conn.close()


@pytest.mark.asyncio
async def test_tunnel_with_dummy():
    async def connect_and_send(ip, port, text):
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(text)
        await writer.drain()

        data = await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return data

    # End to end test with an echo server
    port, dst_port = unused_ports(2)
    async with echo_server(dst_port) as echo, server(port) as srv, client(
        port, dst_port
    ) as cli:
        await asyncio.sleep(0.1)
        assert cli.addr
        for ip_type, port in cli.addr:
            if ip_type == base.InternetType.IPv4:
                assert await connect_and_send("127.0.0.1", port, b"abc") == b"abc"
            elif ip_type == base.InternetType.IPv6:
                assert await connect_and_send("::1", port, b"abc") == b"abc"

        # Close the echo server
        echo.close()
        await echo.wait_closed()

        await asyncio.sleep(0.1)

        for ip_type, port in cli.addr:
            if ip_type == base.InternetType.IPv4:
                assert await connect_and_send("127.0.0.1", port, b"abc") == b""
            elif ip_type == base.InternetType.IPv6:
                assert await connect_and_send("::1", port, b"abc") == b""

        await srv.stop()
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_http_tunnel_with_dummy():
    port, dst_port, http_port = unused_ports(3)

    async with echo_server(dst_port) as echo, http_server(
        port, http_port
    ) as srv, http_client(port, dst_port):

        async def connect_and_send(text):
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                srv.http_port,
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

        assert srv.tunnels
        token = list(srv.tunnels)[0]
        request = b"GET / HTTP/1.1\r\nHost: %s.example.org\r\n\r\n" % token.encode()
        assert await connect_and_send(request) == request

        srv.tunnels[token].protocol = base.ProtocolType.TCP
        assert await connect_and_send(request) == b"HTTP/1.1 404 Not Found\r\n\r\n"

        # Close the echo server
        echo.close()
        await echo.wait_closed()

        await srv.stop()
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_proxy_tunnel_limit():
    (port,) = unused_ports(1)
    async with server(port) as srv:
        reader = writer = mock.AsyncMock(
            feed_eof=mock.MagicMock(), close=mock.MagicMock()
        )
        await asyncio.sleep(0.1)

        srv.max_tunnels = 1
        srv.tunnels = {b"\x00": mock.AsyncMock()}

        await srv._accept(reader, writer)
        assert len(srv.tunnels) == 1


def test_start_functions():
    port, dst_port = unused_ports(2)

    srv = proxy.ProxyServer("", port, cert=None, key=None)
    srv.loop = mock.AsyncMock()
    srv.start()
    assert srv.loop.call_count

    cli = TunnelClient("", port, "", dst_port, None)
    cli.loop = mock.AsyncMock()
    cli.start()
    assert cli.loop.call_count


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
    port, dst_port = unused_ports(2)

    cli = mock.AsyncMock()
    cli.token = b"\x00" * base.CLIENT_NAME_SIZE
    cli.read.return_value = None

    tclient = TunnelClient("", port, "", dst_port, None)
    tclient._disconnect_client = mock.AsyncMock()
    tclient.add(cli)
    tclient.tunnel = mock.AsyncMock()
    tclient.running = True

    # Try connect with existing client
    pkg = package.ClientInitPackage("::1", dst_port, cli.token)
    await tclient._connect_client(pkg)
    assert len(tclient.clients) == 1

    # Close connection while client still running
    cli.reader = asyncio.StreamReader()
    cli.reader.feed_eof()
    await tclient._client_loop(cli)
    assert tclient.tunnel.tun_write.call_count

    # Exception during writing and closing of client
    tclient.running = True
    cli.reader = asyncio.StreamReader()
    cli.read.return_value = b"abc"
    tclient.tunnel.tun_write = tclient.tunnel.tun_data = raiseAssertAsync
    await tclient._client_loop(cli)

    # Invalid package on the tunnel
    tclient.tunnel.tun_read = mock.AsyncMock()
    tclient.tunnel.tun_read.return_value = None
    assert await tclient._handle() is False
    assert tclient.tunnel.tun_read.call_count

    tclient.tunnel.tun_read.return_value = package.Package()
    assert await tclient._handle() is False


@pytest.mark.asyncio
async def test_tunnel_ping():
    port, dst_port = unused_ports(2)

    async with server(port) as srv, client(port, dst_port) as cli:
        # No ping when disabled
        cli.ping_enabled = False
        await cli.idle()
        await asyncio.sleep(0.1)
        assert not cli.last_ping
        assert not cli.last_pong

        # A ping is executed
        cli.ping_enabled = True
        await cli.idle()
        await asyncio.sleep(0.1)
        assert cli.last_ping
        assert cli.last_pong

        # Server sends pong and last_pong updates
        pkg = package.PingPackage(cli.last_ping + 1000)
        cli.last_ping = cli.last_pong = None
        await srv.tunnels[cli.uuid].tunnel.tun_write(pkg)
        await asyncio.sleep(0.1)
        assert cli._check_alive() is True
        assert cli.last_pong

        # Stop the tunnel if time out
        cli.last_ping, cli.last_pong = 0, 2 * base.INTERVAL_TIME
        cli.stop = mock.AsyncMock()
        await cli.idle()
        assert cli.stop.called

        # Check the alive
        cli.last_ping, cli.last_pong = 0, 0.5 * base.INTERVAL_TIME
        assert cli._check_alive() is True

        cli.last_ping = cli.last_pong = None
        assert cli._check_alive() is True

        # Ping too high
        cli.last_ping, cli.last_pong = 0, 100000
        assert cli._check_alive() is False
