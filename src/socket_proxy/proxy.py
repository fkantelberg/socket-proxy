import asyncio
import logging

from . import utils
from .tunnel import TunnelServer

_logger = logging.getLogger(__name__)


# Main proxy server which creates a TLS socket and listens for clients.
# If clients connect the server will start a TunnelServer
class ProxyServer:
    def __init__(
        self, host, port, cert, key, ca=None, max_tunnels=0, **kwargs,
    ):
        self.kwargs = kwargs
        self.host, self.port = host, port
        self.max_tunnels = max_tunnels
        self.tunnels = {}
        self.sc = utils.generate_ssl_context(cert=cert, key=key, ca=ca, server=True)

    # Accept new tunnels and start to listen for clients
    async def _accept(self, reader, writer):
        # Limit the number of tunnels
        if 0 < self.max_tunnels <= len(self.tunnels):
            return

        # Create the tunnel object and generate an unique token
        tunnel = TunnelServer(reader, writer, **self.kwargs)
        self.tunnels[tunnel.token] = tunnel
        try:
            await tunnel.loop()
        finally:
            self.tunnels.pop(tunnel.token)

    # Main server loop to wait for tunnels to open
    async def loop(self):
        self.server = await asyncio.start_server(
            self._accept, self.host, self.port, ssl=self.sc,
        )

        _logger.info("Serving on %s:%s", self.host, self.port)
        async with self.server:
            await self.server.serve_forever()

    # Start the server and event loop
    def start(self):
        _logger.info("Starting server...")
        asyncio.run(self.loop())

    # Stop the server and event loop
    async def stop(self):
        for tunnel in list(self.tunnels.values()):
            await tunnel.stop()

        self.server.close()
        await self.server.wait_closed()
