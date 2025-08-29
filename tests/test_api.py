import asyncio
from unittest import mock

import pytest
from aiohttp import ClientSession, web
from socket_proxy import base

from .common import (
    api_client,
    api_server,
    client,
    echo_server,
    http_client,
    server,
    unused_ports,
)


@pytest.mark.asyncio
async def test_authenticated_tunnel_api():
    (port,) = unused_ports(1)

    async with server(port) as srv:
        srv.authentication = True

        req_mock = mock.AsyncMock(path="/api/token")
        response = await srv._api_index(req_mock)
        token = response.text.strip().replace('"', "")
        assert response.status == 200
        assert srv.tokens[base.AuthType.TOTP][token]
        await asyncio.sleep(0.1)

        req_mock = mock.AsyncMock(path="/api/token/hotp")
        response = await srv._api_index(req_mock)
        token = response.text.strip().replace('"', "")
        assert response.status == 200
        assert token in srv.tokens[base.AuthType.HOTP]
        await asyncio.sleep(0.1)

        srv.authentication = False
        with pytest.raises(web.HTTPNotFound):
            await srv._api_index(req_mock)
        await asyncio.sleep(0.1)

        resp = await srv._api_handle(("invalid",), req_mock)
        assert resp is None
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_api_server():
    port, dst_port, api_port, http_port = unused_ports(4)

    async with (
        echo_server(dst_port),
        api_server(port, http_port, api_port) as srv,
        client(port, dst_port) as cli,
        http_client(port, dst_port),
    ):

        async def connect_and_send(ip, port):
            # Open a connection to get a client
            reader, writer = await asyncio.open_connection(ip, port)
            writer.write(b"hello")
            await writer.drain()

            # Get the client UUID
            async with session.get("/", headers=headers) as response:
                data = await response.json()
                clients = data["exposes"][tuuid]["clients"]
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
        async with ClientSession(f"http://localhost:{api_port}") as session:
            async with session.get("/") as response:
                assert response.status == 200
                data = await response.json()
                print(data)
                print(srv.get_state_dict())
                assert data == srv.get_state_dict()
                assert len(data["exposes"]) == 2

            async with session.get("/tcp") as response:
                assert response.status == 200
                assert await response.json() == srv.get_state_dict()["tcp"]

            async with session.get("/invalid") as response:
                assert response.status == 404

            async with session.get("/api/token") as response:
                assert response.status == 404

            # Activate API token
            srv.api_token = "Bearer abcd"
            headers = {"Authorization": "Bearer abcd"}
            tuuid = cli.uuid
            async with session.get("/") as response:
                assert response.status == 403

            async with session.delete("/") as response:
                assert response.status == 403

            async with session.get("/", headers=headers) as response:
                assert response.status == 200

            for ip_type, port in cli.addr:
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


@pytest.mark.asyncio
async def test_api_client():
    port, dst_port, api_port, http_port = unused_ports(4)

    async with (
        echo_server(dst_port),
        server(port),
        api_client(port, dst_port, http_port, api_port) as cli,
    ):

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
        async with ClientSession(f"http://localhost:{api_port}") as session:
            async with session.get("/") as response:
                assert response.status == 200
                assert await response.json() == cli.get_state_dict()

            async with session.get("/invalid") as response:
                assert response.status == 404

            async with session.get("/tcp") as response:
                assert response.status == 200
                assert await response.json() == cli.get_state_dict()["tcp"]

            # Activate API token
            cli.api_token = "Bearer abcd"
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

            for ip_type, port in cli.addr:
                if ip_type == base.InternetType.IPv4:
                    await connect_and_send("127.0.0.1", port)
                elif ip_type == base.InternetType.IPv6:
                    await connect_and_send("::1", port)
