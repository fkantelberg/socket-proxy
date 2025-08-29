import asyncio
import enum
import logging
import ssl
from typing import Any, Optional, Sequence

from . import base, utils

try:
    from aiohttp import web
    from aiohttp.web import Application, AppRunner, Request, Response, TCPSite
except ImportError:
    web = Application = AppRunner = Request = Response = TCPSite = None  # type: ignore

_logger = logging.getLogger(__name__)


class APIType(enum.IntEnum):
    Client = 0x01
    Server = 0x02
    Bridge = 0x03


async def run_app(
    api: Application,
    host: Optional[str] = None,
    port: Optional[int] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> AppRunner:
    app = AppRunner(
        api,
        access_log_format='%a "%r" %s %b "%{Referer}i" "%{User-Agent}i"',
    )
    await app.setup()

    site = TCPSite(
        app,
        host=host,
        port=port,
        reuse_address=True,
        reuse_port=True,
        ssl_context=ssl_context,
    )
    await site.start()


class APIMixin:
    """Mixin to define the basic API implementations"""

    def __init__(self, api_type: APIType):
        self.api_type: APIType = api_type
        self.api: Optional[AppRunner] = None
        self.api_ssl: bool = False
        self.api_host: Optional[str] = None
        self.api_port: Optional[int] = None
        self.api_token: Optional[str] = None

        if web is None:
            return

        self.api_ssl = base.config.api_ssl if self.api_type == APIType.Server else None

        if base.config.api:
            api_token = base.config.api_token
            self.api_token = f"Bearer {api_token}" if api_token else None
            self.api_host, self.api_port = base.config.api_listen

    async def disconnect(self, *_uuids: str) -> bool:
        """Handle the disconnect over the API"""
        return False

    # pylint: disable=W0613
    async def _api_handle(self, path: Sequence[str], request: Request) -> Any:
        """Handle api functions"""
        return None

    async def _api_index(self, request: Request) -> Response:
        """Response with the internal server state"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        path: Sequence[str] = tuple(filter(None, request.path.split("/")))
        if "api" in path[:1]:
            data = await self._api_handle(path[1:], request)
            if data is not None:
                return web.json_response(data)
            raise web.HTTPNotFound()

        data = self.get_state_dict()
        try:
            data = utils.traverse_dict(data, *path)
        except KeyError as e:
            raise web.HTTPNotFound() from e

        return web.json_response(data)

    async def _api_delete(self, request: Request) -> Response:
        """Disconnect a specific tunnel/client"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        uuids: Sequence[str] = list(filter(None, request.path.split("/")))
        if await self.disconnect(*uuids):
            raise web.HTTPOk()
        raise web.HTTPNotFound()

    async def start_api(self) -> None:
        """Start the API"""
        extras = [
            "tls" if self.api_type == APIType.Server and self.api_ssl else "",
            "token" if self.api_token else "",
        ]
        extras = sorted(filter(None, extras))
        flags = f"[{','.join(extras)}]" if extras else ""

        _logger.info(f"Starting API on {self.api_host}:{self.api_port} {flags}")
        self.api = web.Application()
        self.api.add_routes(
            [
                web.get(r"/{name:.*}", self._api_index),
                web.delete(r"/{name:.*}", self._api_delete),
            ]
        )

        self.app = await run_app(
            self.api,
            host=self.api_host,
            port=self.api_port,
            ssl_context=self.sc if self.api_ssl else None,
        )

        while True:
            await asyncio.sleep(60)
