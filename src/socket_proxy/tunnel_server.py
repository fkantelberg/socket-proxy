import asyncio
import collections
import ipaddress
import logging
from asyncio import StreamReader, StreamWriter
from datetime import datetime, timedelta
from typing import List, Tuple

from . import base, package, tunnel, utils
from .connection import Connection

_logger = logging.getLogger(__name__)


class TunnelServer(tunnel.Tunnel):
    """Server side of the tunnel to listen for external connections"""

    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        *,
        domain: str = "",
        tunnel_host: str = None,
        ports: Tuple[int, int] = None,
        protocols: List[base.ProtocolType] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.tunnel = Connection(reader, writer, token=utils.generate_token())
        self.domain = f"{self.uuid}.{domain}" if domain else ""
        self.host, self.port = writer.get_extra_info("peername")[:2]
        self.tunnel_host = tunnel_host.split(",") if tunnel_host else ""
        self.tunnel_port = None
        self.ports = ports
        self.server = None
        self.connections = collections.defaultdict(utils.Ban)
        self.protocols = protocols or utils.protocols()

    def block(self, ip: base.IPvXAddress) -> bool:
        """Decide whether the ip should be blocked"""
        if 0 < self.max_connects <= self.connections[ip].hits:
            return True

        if self.networks and not any(ip in n for n in self.networks):
            return True

        return False

    async def idle(self) -> None:
        await super().idle()

        # Clear the connections
        dt = datetime.now() - timedelta(seconds=self.bantime)
        for ip, ban in list(self.connections.items()):
            if ban.first < dt:
                self.connections.pop(ip)
                _logger.info("Connection number of %s resetted", ip)

    async def _client_accept(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        read_ahead: bytes = None,
    ) -> None:
        """Accept new clients and inform the tunnel about connections"""
        host, port = writer.get_extra_info("peername")[:2]
        ip = ipaddress.ip_address(host)

        # Block connections using the networks
        if self.block(ip):
            reader.feed_eof()
            writer.close()
            await writer.wait_closed()

            _logger.info("Connection from %s blocked", ip)
            return

        self.connections[ip].hits += 1

        # Create the client object and generate an unique token
        client = Connection(reader, writer, self.protocol, utils.generate_token())
        self.add(client)

        _logger.info("Client %s connected on %s:%s", client.uuid, host, port)

        # Inform the tunnel about the new client
        pkg = package.ClientInitPackage(ip, port, client.token)
        await self.tunnel.tun_write(pkg)

        # Send the buffer read ahead of initialization through the tunnel
        if read_ahead:
            await self.tunnel.tun_data(client.token, read_ahead)

        # Serve data from the client
        while True:
            data = await client.read(self.chunk_size)
            # Client disconnected. Inform the tunnel
            if not data:
                break

            await self.tunnel.tun_data(client.token, data)

        if self.server and self.server.is_serving():
            pkg = package.ClientClosePackage(client.token)
            await self.tunnel.tun_write(pkg)

        await self._disconnect_client(client.token)

    async def _open_server(self) -> bool:
        """Open the public server listener and start the main loop"""

        # Start to listen on an external port
        self.tunnel_port = utils.get_unused_port(*self.ports) if self.ports else 0
        if self.tunnel_port is None:
            self.error("All ports are blocked")
            await self.stop()
            return False

        self.server = await asyncio.start_server(
            self._client_accept,
            self.tunnel_host,
            self.tunnel_port,
        )
        asyncio.create_task(self._client_loop())
        return True

    async def _client_loop(self) -> None:
        """Main client loop initializing the client and managing the transmission"""
        self.addr = [sock.getsockname()[:2] for sock in self.server.sockets]

        # Initialize the tunnel by sending the appropiate data
        out = " ".join(sorted(f"{host}:{port}" for host, port in self.addr))
        self.info("Listen on %s", out)

        addr = [(base.InternetType.from_ip(ip), ip, port) for ip, port in self.addr]
        pkg = package.InitPackage(self.token, addr, self.domain)
        await self.tunnel.tun_write(pkg)

        # Start listening
        async with self.server:
            await self.server.serve_forever()

    async def _handle(self) -> bool:
        pkg = await self.tunnel.tun_read()
        # Start the server
        if isinstance(pkg, package.ConnectPackage):
            self.protocol = pkg.protocol
            if self.protocol not in self.protocols:
                self.error(f"Disabled protocol {self.protocol.name}")
                return False

            self.info("Using protocol: %s", self.protocol.name)

            if self.protocol != base.ProtocolType.TCP:
                self.info("Reachable with domain: %s", self.domain)
                pkg = package.InitPackage(self.token, [], self.domain)
                await self.tunnel.tun_write(pkg)
            elif not await self._open_server():
                return await super()._handle()

            return True

        # Handle configuration
        if isinstance(pkg, package.ConfigPackage):
            self.config_from_package(pkg)
            await self._send_config()
            return True

        # Handle a ping package and reply
        if isinstance(pkg, package.PingPackage):
            await self.tunnel.tun_write(pkg)
            return True

        # Handle a closed client
        if isinstance(pkg, package.ClientClosePackage):
            await self._disconnect_client(pkg.token)
            return True

        # Handle data coming through the tunnel
        if isinstance(pkg, package.ClientDataPackage):
            # Check for valid tokens
            if pkg.token not in self:
                self.error("Invalid client token: %s", pkg.token)
                return False

            conn = self[pkg.token]
            await conn.write(pkg.data)
            return True

        # Invalid package means to close the connection
        if pkg is not None:
            self.error("Invalid package: %s", pkg)
            return await super()._handle()

        return await super()._handle()

    async def stop(self) -> None:
        """Stop everything"""
        await super().stop()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self.info("closed")

    async def loop(self) -> None:
        """Main loop of the proxy tunnel"""
        ssl_obj = self.tunnel.writer.get_extra_info("ssl_object")
        extra = f" [{ssl_obj.version()}]" if ssl_obj else ""
        self.info("Connected %s:%s%s", self.host, self.port, extra)

        try:
            await self._serve()
        finally:
            await self.stop()
