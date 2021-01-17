import asyncio
import json
import logging

from . import base, package, tunnel, utils
from .config import config
from .connection import Connection

_logger = logging.getLogger(__name__)


class TunnelClient(tunnel.Tunnel):
    """ Client side of the tunnel which will connect to a ProxyServer """

    def __init__(
        self,
        host: str,
        port: int,
        dst_host: str,
        dst_port: int,
        ca: str,
        cert: str = None,
        key: str = None,
        verify_hostname: bool = True,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.host, self.port = host, port
        self.dst_host, self.dst_port = dst_host, dst_port
        self.running = False
        self.addresses = []

        self.sc = utils.generate_ssl_context(
            cert=cert, key=key, ca=ca, check_hostname=verify_hostname,
        )

    def info(self, msg: str, *args) -> None:
        _logger.info(msg.capitalize(), *args)

    def error(self, msg: str, *args) -> None:
        _logger.error(msg.capitalize(), *args)

    async def _client_loop(self, client: Connection) -> None:
        """ This is the main client loop """
        _logger.info("Client %s connected", client.token.hex())
        while True:
            data = await client.read(self.chunk_size)
            if not data:
                await self._disconnect_client(client.token)
                break

            try:
                await self.tunnel.tun_data(client.token, data)
            except Exception:
                break

        if self.running:
            try:
                pkg = package.ClientClosePackage(client.token)
                await self.tunnel.tun_write(pkg)
            except Exception:
                pass

    async def _connect_client(self, pkg: package.Package) -> None:
        """ Handles the connection of a new client through the tunnel """
        if pkg.token in self:
            return

        try:
            # We have to connect to the specific target
            client = await Connection.connect(self.dst_host, self.dst_port, pkg.token)

            self.add(client)
            asyncio.create_task(self._client_loop(client))
            return
        except Exception:
            _logger.error("Client connection failed")
            pkg = package.ClientClosePackage(pkg.token)
            await self.tunnel.tun_write(pkg)

    async def _send_data(self, pkg: package.Package) -> None:
        """ Send data through the tunnel to the server side of the tunnel """
        client = self.get(pkg.token)
        if client:
            client.write(pkg.data)
            await client.drain()

    def store_information(self) -> None:
        fp = config.get("store-information")
        if not fp:
            return

        json.dump(
            {
                "protocol": self.protocol.name,
                "dest": [self.dst_host, self.dst_port],
                "host": self.host,
                "ports": [[ip_type.name, port] for ip_type, port in self.addresses],
                "domain": self.domain,
            },
            fp,
        )

    async def _handle(self) -> bool:
        # We need the next package and try to evaluate it
        pkg = await self.tunnel.tun_read()

        # The tunnel was initialized
        if isinstance(pkg, package.InitPackage):
            self.tunnel.token = pkg.token
            self.addresses = pkg.addresses
            self.domain = pkg.domain

            # Output the public addresses
            for ip_type, port in sorted(self.addresses):
                self.info("open: %s on port %s", ip_type.name, port)

            if self.protocol == base.ProtocolType.HTTP:
                self.info("domain: %s", self.domain)

            # Store information into a file
            self.store_information()

            # Send the configuration to the server for negotiation
            await self._send_config()
            return True

        # Configuration comes back from the server we use that
        if isinstance(pkg, package.ConfigPackage):
            self.config_from_package(pkg)
            return True

        # A new client connected on the other side of the tunnel
        if isinstance(pkg, package.ClientInitPackage):
            await self._connect_client(pkg)
            return True

        # A client disconnected from the other side of the tunnel
        if isinstance(pkg, package.ClientClosePackage):
            await self._disconnect_client(pkg.token)
            return True

        # Manage data coming through the tunnel
        if isinstance(pkg, package.ClientDataPackage):
            await self._send_data(pkg)
            return True

        # Something unexpected happened
        if pkg is not None:
            self.error("invalid package: %s", pkg)
            return await super()._handle()

        return await super()._handle()

    async def loop(self) -> None:
        """ Main client loop of the client side of the tunnel """
        self.tunnel = await Connection.connect(self.host, self.port, ssl=self.sc)
        _logger.info("Tunnel %s:%s connected", self.host, self.port)
        _logger.info("Forwarding to %s:%s", self.dst_host, self.dst_port)

        try:
            # Start the tunnel and send the initial package
            self.running = True
            pkg = package.ConnectPackage(self.protocol)
            await self.tunnel.tun_write(pkg)
            await self._serve()
        finally:
            self.running = False
            await self.stop()
            _logger.info("Tunnel %s:%s closed", self.host, self.port)

    def start(self) -> None:
        """ Start the client and the event loop """
        _logger.info("Starting client...")
        asyncio.run(self.loop())
