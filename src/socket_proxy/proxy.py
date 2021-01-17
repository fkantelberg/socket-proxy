import asyncio
import logging
import re
from asyncio import StreamReader, StreamWriter
from typing import List, Union

from . import base, utils
from .config import config
from .tunnel_server import TunnelServer

_logger = logging.getLogger(__name__)

HTTPRequestStatus = re.compile(rb"^(\S+)\s+(\S+)\s+(\S+)$")


class ProxyServer:
    """ Main proxy server which creates a TLS socket and listens for clients.
        If clients connect the server will start a TunnelServer """

    def __init__(
        self,
        host: Union[str, List[str]],
        port: int,
        cert: str,
        key: str,
        ca: str = None,
        http_domain: str = None,
        **kwargs,
    ):
        self.kwargs = kwargs
        self.host, self.port = host, port
        self.max_tunnels = config["max-tunnels"]
        self.http_host, self.http_port = config["http-listen"]
        self.tunnels = {}
        self.sc = utils.generate_ssl_context(cert=cert, key=key, ca=ca, server=True)

        if isinstance(http_domain, str):
            self.http_domain = http_domain
            self.http_domain_regex = re.compile(
                rb"^(.*)\.%s$" % http_domain.replace(".", r"\.").encode()
            )
        else:
            self.http_domain = self.http_domain_regex = False

    async def _accept(self, reader: StreamReader, writer: StreamWriter) -> None:
        """ Accept new tunnels and start to listen for clients """

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
        """ Handle http requests and try to proxy them to the specific tunnel """
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
                headers[header] = value

        # Extract the host from the headers and try matching them
        host = headers.get(b"X-Forwarded-Host", headers.get(b"Host", b""))
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
        """ Main server loop for the http socket """
        host = self.http_host
        for h in host if isinstance(host, list) else [host]:
            _logger.info("Serving on %s:%s [HTTP]", h, self.http_port)

        self.http_proxy = await asyncio.start_server(
            self._request, self.http_host, self.http_port,
        )

        async with self.http_proxy:
            await self.http_proxy.serve_forever()

    async def loop(self) -> None:
        """ Main server loop to wait for tunnels to open """
        if self.http_domain_regex:
            asyncio.create_task(self.http_loop())

        self.server = await asyncio.start_server(
            self._accept, self.host, self.port, ssl=self.sc,
        )

        for host in self.host if isinstance(self.host, list) else [self.host]:
            _logger.info("Serving on %s:%s", host, self.port)

        async with self.server:
            await self.server.serve_forever()

    def start(self) -> None:
        """ Start the server and event loop """
        _logger.info("Starting server...")
        asyncio.run(self.loop())

    async def stop(self) -> None:
        """ Stop the server and event loop """
        for tunnel in self.tunnels.values():
            await tunnel.stop()

        self.server.close()
        await self.server.wait_closed()

    async def close(self, reader: StreamReader, writer: StreamWriter) -> None:
        """ Close a StreamReader and StreamWriter """
        reader.feed_eof()
        writer.close()
        await writer.wait_closed()
