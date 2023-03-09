import asyncio
import subprocess
from contextlib import asynccontextmanager
from unittest import mock

from socket_proxy import TunnelClient, base, proxy, utils

CA_CERT = "pki/ca.pem"
CLIENT_CERT = "pki/client.pem"
CLIENT_KEY = "pki/client.key"
SERVER_CERT = "pki/server.pem"
SERVER_KEY = "pki/server.key"
CRL = "pki/crl.pem"

with subprocess.Popen(["./certs.sh", "client"], stdin=subprocess.PIPE) as proc:
    proc.communicate()
with subprocess.Popen(["./certs.sh", "server"], stdin=subprocess.PIPE) as proc:
    proc.communicate(b"y\n" * 80)


# pylint: disable=W0613


def raiseAssertAsync(*args, **kwargs):
    raise AssertionError()


def unused_ports(n, min_port=5000, max_port=10000):
    return [utils.get_unused_port(min_port, max_port) for _ in range(n)]


@asynccontextmanager
async def echo_server(port):
    async def accept(reader, writer):
        data = await reader.read(1024)
        writer.write(data)
        await writer.drain()

        writer.close()
        await writer.wait_closed()

    async def loop(server):
        async with server:
            await server.serve_forever()

    server = await asyncio.start_server(accept, host="", port=port)
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(loop(server))
    await asyncio.sleep(0.1)
    yield server
    server.close()
    await server.wait_closed()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def server(port):
    base.config.api = False

    server = proxy.ProxyServer(
        host="",
        port=port,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
    )
    server._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def client(port, dst_port):
    base.config.api = False

    client = TunnelClient(
        host="localhost",
        port=port,
        dst_host="localhost",
        dst_port=dst_port,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
    )
    client._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(client.loop())
    await asyncio.sleep(0.1)
    yield client
    await client.stop()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def http_server(port, http_port):
    base.config.api = False
    base.config.http_domain = "example.org"
    base.config.http_listen = "127.0.0.1", http_port

    server = proxy.ProxyServer(
        host="",
        port=port,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
        protocols=[base.ProtocolType.HTTP],
    )
    server._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def api_server(port, http_port, api_port):
    base.config.api = True
    base.config.api_listen = "127.0.0.1", api_port
    base.config.http_listen = "127.0.0.1", http_port

    server = proxy.ProxyServer(
        host="",
        port=port,
        cert=SERVER_CERT,
        key=SERVER_KEY,
        ca=CA_CERT,
        crl=CRL,
        protocols=[base.ProtocolType.TCP, base.ProtocolType.HTTP],
    )
    server._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(server.loop())
    await asyncio.sleep(0.1)
    yield server
    await server.stop()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def api_client(port, dst_port, http_port, api_port):
    base.config.api = True
    base.config.api_listen = "127.0.0.1", api_port
    base.config.http_listen = "127.0.0.1", http_port

    client = TunnelClient(
        host="localhost",
        port=port,
        dst_host="localhost",
        dst_port=dst_port,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
    )
    client._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(client.loop())
    await asyncio.sleep(0.1)
    yield client
    await client.stop()
    await asyncio.sleep(0.1)


@asynccontextmanager
async def http_client(port, dst_port):
    base.config.api = False

    client = TunnelClient(
        host="localhost",
        port=port,
        dst_host="localhost",
        dst_port=dst_port,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT,
        protocol=base.ProtocolType.HTTP,
    )
    client._interval = mock.AsyncMock()
    event_loop = asyncio.get_event_loop()
    event_loop.create_task(client.loop())
    await asyncio.sleep(0.1)
    yield client
    await client.stop()
    await asyncio.sleep(0.1)
