import enum
import logging
from typing import Tuple

from . import base, utils

try:
    from aiohttp import web
    from aiohttp.web import Request, Response
except ImportError:
    web = Request = Response = None

_logger = logging.getLogger(__name__)


class APIType(enum.IntEnum):
    Client = 0x01
    Server = 0x02


class APIMixin:
    def __init__(self, api_type: APIType):
        self.api_type = api_type
        self.api = None
        self.api_host = self.api_port = self.api_token = False
        self.api_ssl = base.config.api_ssl if self.api_type == APIType.Server else None

        if base.config.api:
            api_token = base.config.api_token
            self.api_token = f"Bearer {api_token}" if api_token else None
            self.api_host, self.api_port = base.config.api_listen

    async def disconnect(self, *uuids: Tuple[str]) -> bool:
        """Handle the disconnect over the API"""

    async def _api_index(self, request: Request) -> Response:
        """Response with the internal server state"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        data = self.get_state_dict()
        try:
            data = utils.traverse_dict(data, *request.path.split("/"))
        except KeyError as e:
            raise web.HTTPNotFound() from e

        return web.json_response(data)

    async def _api_delete(self, request: Request) -> Response:
        """Disconnect a specific tunnel/client"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        uuids = list(filter(None, request.path.split("/")))
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
        extras = f"[{','.join(extras)}]" if extras else ""

        _logger.info("Starting API on %s:%s %s", self.api_host, self.api_port, extras)
        self.api = web.Application()
        self.api.add_routes(
            [
                web.get(r"/{name:.*}", self._api_index),
                web.delete(r"/{name:.*}", self._api_delete),
            ]
        )

        await web._run_app(
            self.api,
            host=self.api_host,
            port=self.api_port,
            access_log_format='%a "%r" %s %b "%{Referer}i" "%{User-Agent}i"',
            reuse_address=True,
            reuse_port=True,
            print=None,
            ssl_context=self.sc if self.api_ssl else None,
        )
