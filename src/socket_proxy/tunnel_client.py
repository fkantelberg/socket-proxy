import asyncio
import logging

from . import base, package, tunnel, utils
from .connection import Connection

_logger = logging.getLogger(__name__)


class TunnelClient(tunnel.Tunnel):
    """ Client side of the tunnel which will connect to a ProxyServer """

    def __init__(
        self,
        host,
        port,
        dst_host,
        dst_port,
        ca,
        cert=None,
        key=None,
        verify_hostname=True,
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

    def info(self, msg, *args):
        _logger.info(msg.capitalize(), *args)

    def error(self, msg, *args):
        _logger.error(msg.capitalize(), *args)

    async def _client_loop(self, client):
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

    async def _connect_client(self, pkg):
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

    async def _send_data(self, pkg):
        """ Send data through the tunnel to the server side of the tunnel """
        client = self.get(pkg.token)
        if client:
            client.write(pkg.data)
            await client.drain()

    async def _serve(self):
        """ Main loop which will listen on the tunnel for packages """
        await super()._serve()

        while True:
            # We need the next package and try to evaluate it
            pkg = await self.tunnel.tun_read()

            if isinstance(pkg, package.InitPackage):
                # The tunnel was initialized
                self.tunnel.token = pkg.token
                self.addresses = pkg.addresses
                self.domain = pkg.domain

                # Output the public addresses
                for ip_type, port in sorted(self.addresses):
                    self.info("open: %s on port %s", ip_type.name, port)

                if self.protocol == base.ProtocolType.HTTP:
                    self.info("domain: %s", self.domain)

                # Send the configuration to the server for negotiation
                await self._send_config()
            elif isinstance(pkg, package.ConfigPackage):
                # Configuration comes back from the server we use that
                self.config_from_package(pkg)
            elif isinstance(pkg, package.ClientInitPackage):
                # A new client connected on the other side of the tunnel
                await self._connect_client(pkg)
            elif isinstance(pkg, package.ClientClosePackage):
                # A client disconnected from the other side of the tunnel
                await self._disconnect_client(pkg.token)
            elif isinstance(pkg, package.ClientDataPackage):
                # Manage data coming through the tunnel
                await self._send_data(pkg)
            elif pkg is not None:
                # Something unexpected happend
                self.error("invalid package: %s", pkg)
                break
            else:
                break

    async def loop(self):
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

    def start(self):
        """ Start the client and the event loop """
        _logger.info("Starting client...")
        asyncio.run(self.loop())
