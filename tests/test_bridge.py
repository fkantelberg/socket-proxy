import asyncio

import pytest
from socket_proxy import base

from .common import bridge, client, connect_and_send, echo_server, server, unused_ports


@pytest.mark.asyncio
async def test_bridge():
    port, dst_port = unused_ports(2)
    async with (
        echo_server(dst_port),
        server(port) as srv,
        client(port, dst_port, protocol=base.ProtocolType.BRIDGE) as cli,
    ):
        await asyncio.sleep(0.1)

        assert srv.bridge_servers
        assert not cli.addr
        assert cli.bridge_token

        assert srv.get_state_dict()["bridges"]

        async with bridge(port, cli.bridge_token) as bri:
            await asyncio.sleep(0.1)
            assert len(bri.addr) == 2

            for ip, port in bri.addr:
                host = base.InternetType.from_ip(ip).localhost()
                assert await connect_and_send(host, port, b"abc") == b"abc"
