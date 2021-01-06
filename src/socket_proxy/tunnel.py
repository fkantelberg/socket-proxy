import asyncio
import logging
import time

from . import base, package, utils
from .config import config

_logger = logging.getLogger(__name__)


class Tunnel:
    """ Generic implementation of the tunnel """

    def __init__(
        self,
        *,
        domain="",
        protocol=base.ProtocolType.TCP,
        chunk_size=65536,
        networks=None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.tunnel = None
        self.clients = {}
        self.protocol = protocol
        self.domain = domain or ""
        self.chunk_size = chunk_size
        self.bantime = config["ban-time"]
        self.max_clients = config["max-clients"]
        self.max_connects = config["max-connects"]
        self.idle_timeout = config["idle-timeout"]
        self.networks = networks or []

    def __contains__(self, token):
        return token in self.clients

    def __getitem__(self, token):
        return self.clients[token]

    @property
    def token(self):
        return self.tunnel.token

    @property
    def uuid(self):
        return self.tunnel.uuid

    def info(self, msg, *args):
        _logger.info("Tunnel %s " + msg, self.uuid, *args)

    def error(self, msg, *args):
        _logger.error("Tunnel %s " + msg, self.uuid, *args)

    def add(self, client):
        if client.token in self.clients:
            return

        if 0 < self.max_clients <= len(self.clients):
            raise base.ReachedClientLimit()

        self.clients[client.token] = client

    def get(self, token):
        return self.clients.get(token, None)

    def pop(self, token):
        return self.clients.pop(token, None)

    def config_from_package(self, pkg):
        """ Merge the configuration with the current one """
        self.bantime = utils.merge_settings(self.bantime, pkg.bantime)
        self.max_clients = utils.merge_settings(self.max_clients, pkg.clients)
        self.max_connects = utils.merge_settings(self.max_connects, pkg.connects)
        self.idle_timeout = utils.merge_settings(self.idle_timeout, pkg.idle_timeout)
        self.networks = utils.optimize_networks(*self.networks, *pkg.networks)

        # Just output the current configuration
        networks = self.networks if self.networks else ["0.0.0.0/0", "::/0"]
        self.info(f"Allowed networks: {', '.join(map(str, networks))}")
        self.info(f"ban time: {self.bantime or 'off'}")
        self.info(f"clients: {self.max_clients or '-'}")
        self.info(f"idle timeout: {self.idle_timeout or 'off'}")
        self.info(f"connections per IP: {self.max_connects or '-'}")

    async def _disconnect_client(self, token):
        """ Disconnect a client """
        client = self.pop(token)
        if client:
            _logger.info("Client %s disconnected", token.hex())
            await client.close()

    async def idle(self):
        """ This methods will get called regularly to apply timeouts """
        if self.idle_timeout and self.tunnel:
            if time.time() - self.tunnel.last_time > self.idle_timeout:
                self.info("timeout")
                await self.stop()

    async def stop(self):
        """ Disconnects all clients and stop the tunnel """
        for client in list(self.clients.values()):
            await client.close()

        if self.tunnel:
            await self.tunnel.close()

    async def _handle(self):
        """ Basic handler of the tunnel. Return False to leave the main loop """
        return False

    async def _serve(self):
        """ Main tunnel loop """
        asyncio.create_task(self._interval())

        while await self._handle():
            pass

    async def _send_config(self):
        """ Send the current configuration as a package through the tunnel """
        pkg = package.ConfigPackage(
            self.bantime,
            self.max_clients,
            self.max_connects,
            self.idle_timeout,
            self.networks,
        )
        await self.tunnel.tun_write(pkg)

    async def _interval(self):
        """ Calls regularly the idle function """
        while True:
            await self.idle()
            await asyncio.sleep(base.INTERVAL_TIME)
