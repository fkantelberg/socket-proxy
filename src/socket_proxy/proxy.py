import asyncio
import logging
import re
from asyncio import StreamReader, StreamWriter
from typing import List, Tuple, Union

from . import base, utils
from .tunnel_server import TunnelServer

try:
    from aiohttp import web
    from aiohttp.web import Request, Response
except ImportError:
    web = Request = Response = None

_logger = logging.getLogger(__name__)

HTTPRequestStatus = re.compile(rb"^(\S+)\s+(\S+)\s+(\S+)$")


class ProxyServer:
    """Main proxy server which creates a TLS socket and listens for clients.
    If clients connect the server will start a TunnelServer"""

    def __init__(
        self,
        host: Union[str, List[str]],
        port: int,
        cert: str,
        key: str,
        ca: str = None,
        crl: str = None,
        http_domain: str = None,
        http_ssl: bool = False,
        http_listen: Tuple[Union[str, List[str]], int] = None,
        api_listen: Tuple[Union[str, List[str]], int] = None,
        api_token: str = None,
        api_ssl: bool = False,
        **kwargs,
    ):
        self.kwargs = kwargs
        self.host, self.port = host, port
        self.max_tunnels = base.config.max_tunnels
        self.http_ssl = http_ssl
        self.api_ssl = api_ssl
        self.tunnels = {}
        self.sc = utils.generate_ssl_context(
            cert=cert,
            key=key,
            ca=ca,
            crl=crl,
            server=True,
        )
        self.api = self.http_proxy = self.server = None

        self.api_token = f"Bearer {api_token}" if api_token else None
        if api_listen:
            self.api_host, self.api_port = api_listen
        else:
            self.api_host = self.api_port = False

        if isinstance(http_domain, str) and http_listen:
            self.http_host, self.http_port = http_listen
            self.http_domain = http_domain
            self.http_domain_regex = re.compile(
                rb"^(.*)\.%s$" % http_domain.replace(".", r"\.").encode()
            )
        else:
            self.http_host = self.http_port = False
            self.http_domain = self.http_domain_regex = False

    async def _accept(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Accept new tunnels and start to listen for clients"""

        # Limit the number of tunnels
        if 0 < self.max_tunnels <= len(self.tunnels):
            return

        # Create the tunnel object and generate an unique token
        tunnel = TunnelServer(reader, writer, domain=self.http_domain, **self.kwargs)
        self.tunnels[tunnel.uuid] = tunnel
        try:
            await tunnel.loop()
        finally:
            self.tunnels.pop(tunnel.uuid)

    async def _request(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Handle http requests and try to proxy them to the specific tunnel"""
        buf = await reader.readline()
        status = buf.strip()
        match = HTTPRequestStatus.match(status)
        if not match:
            await self.close(reader, writer)
            return

        version = match.groups()[2]

        # Read the HTTP headers
        headers = {}
        while not reader.at_eof():
            line = await reader.readline()
            buf += line

            stripped = line.strip()
            if not stripped:
                break

            if b":" in stripped:
                header, value = (x.strip() for x in stripped.split(b":", 1))
                headers[header.lower()] = value

        # Extract the host from the headers and try matching them
        host = headers.get(b"x-forwarded-host", headers.get(b"host", b""))
        match = self.http_domain_regex.match(host)
        if not match or len(match.groups()) < 1:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)
            return

        # Find the right tunnel for the host
        tun_uuid = match.groups()[0].decode()
        if tun_uuid not in self.tunnels:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)
            return

        # Get the tunnel and accept the client if set to HTTP protocol
        tunnel = self.tunnels[tun_uuid]
        if tunnel.protocol == base.ProtocolType.HTTP:
            await tunnel._client_accept(reader, writer, buf)
        else:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)

    async def http_loop(self) -> None:
        """Main server loop for the http socket"""
        host = self.http_host
        for h in host if isinstance(host, list) else [host]:
            _logger.info("Serving on %s:%s [HTTP]", h, self.http_port)

        self.http_proxy = await asyncio.start_server(
            self._request,
            self.http_host,
            self.http_port,
            ssl=self.sc if self.http_ssl else None,
        )

        async with self.http_proxy:
            await self.http_proxy.serve_forever()

    async def loop(self) -> None:
        """Main server loop to wait for tunnels to open"""
        if self.http_domain_regex:
            asyncio.create_task(self.http_loop())

        if self.api_port:
            asyncio.create_task(self._start_api())

        self.server = await asyncio.start_server(
            self._accept,
            self.host,
            self.port,
            ssl=self.sc,
        )

        for host in self.host if isinstance(self.host, list) else [self.host]:
            _logger.info("Serving on %s:%s", host, self.port)

        async with self.server:
            await self.server.serve_forever()

    def get_state_dict(self) -> dict:
        """Generate a dictionary which shows the current state of the server"""
        tunnels = {}
        for tuuid, tunnel in self.tunnels.items():
            tunnels[tuuid] = tunnel.get_state_dict()

        http = {
            "domain": self.http_domain,
            "host": self.http_host,
            "port": self.http_port,
        }

        return {
            "http": http if self.http_domain else {},
            "tcp": {
                "host": self.host,
                "port": self.port,
            },
            "tunnels": tunnels,
        }

    async def _api_index(self, request: Request) -> Response:
        """Response with the internal server state"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        data = self.get_state_dict()
        for key in filter(None, request.path.split("/")):
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                data = {}
                raise web.HTTPNotFound()

        return web.json_response(data)

    async def _api_delete(self, request: Request) -> Response:
        """Disconnect a specific tunnel or client"""
        if self.api_token and self.api_token != request.headers.get("Authorization"):
            raise web.HTTPForbidden()

        keys = list(filter(None, request.path.split("/")))
        if len(keys) < 1 or keys[0] not in self.tunnels:
            raise web.HTTPNotFound()

        tunnel = self.tunnels[keys[0]]
        if len(keys) == 1:
            await tunnel.stop()
            raise web.HTTPOk()

        for ctoken, cli in tunnel.clients.items():
            if cli.uuid == keys[1]:
                await tunnel._disconnect_client(ctoken)
                raise web.HTTPOk()

        raise web.HTTPNotFound()

    async def _start_api(self) -> None:
        """Start the API"""
        extras = [
            "tls" if self.api_ssl else "",
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
            print=None,
            ssl_context=self.sc if self.api_ssl else None,
        )

    def start(self) -> None:
        """Start the server and event loop"""
        _logger.info("Starting server...")
        asyncio.run(self.loop())

    async def stop(self) -> None:
        """Stop the server and event loop"""
        for tunnel in self.tunnels.values():
            await tunnel.stop()

        if self.api:
            await self.api.cleanup()
            await self.api.shutdown()

        self.server.close()
        await self.server.wait_closed()

    async def close(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Close a StreamReader and StreamWriter"""
        reader.feed_eof()
        writer.close()
        await writer.wait_closed()
