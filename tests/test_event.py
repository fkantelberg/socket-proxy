import asyncio

import pytest
from aiohttp import web

from socket_proxy import api, event

from .common import unused_ports


@pytest.mark.asyncio
async def test_event_system():
    counter = 0
    status = 200

    async def receive(request: web.Request) -> web.Response:
        nonlocal counter, status
        counter += 1
        data = await request.json()
        assert isinstance(data, dict)
        assert data["message"] == "testing"
        return web.Response(status=status)

    port, port2 = unused_ports(2)

    app = web.Application()
    app.add_routes([web.post("/", receive)])
    asyncio.create_task(api.run_app(app, host="127.0.0.1", port=port))
    await asyncio.sleep(0.1)

    system = event.EventSystem(event.EventType.Server, url=None, token=None)
    assert not system.enabled
    system.send_nowait(msg="testing")
    await system.send(msg="testing")
    assert system.queue.empty()
    await system.flush()
    await asyncio.sleep(0.1)
    assert counter == 0

    system = event.EventSystem(event.EventType.Server, url=f"http://localhost:{port}")
    assert system.enabled
    system.send_nowait(msg="testing")
    await system.send(msg="testing")
    assert not system.queue.empty()
    await system.flush()
    await asyncio.sleep(0.1)
    assert counter == 2

    status = 404
    await system.send(msg="testing")
    await system.flush()
    await asyncio.sleep(0.1)
    assert not system.queue.empty()

    system = event.EventSystem(event.EventType.Server, url=f"http://localhost:{port2}")
    await system.send(msg="testing")
    await system.flush()
    await asyncio.sleep(0.1)
    assert not system.queue.empty()
