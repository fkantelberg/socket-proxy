import asyncio
import logging
import time
from datetime import datetime
from ipaddress import ip_network
from typing import Any, Dict, Optional

from . import base, package, utils
from .connection import Connection

_logger = logging.getLogger(__name__)


class Tunnel:
    """Generic implementation of the tunnel"""

    def __init__(
        self,
        *,
        domain: str = "",
        protocol: base.ProtocolType = base.ProtocolType.TCP,
        chunk_size: int = 65536,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.addr: base.IPvXPorts = []
        self.tunnel: Optional[Connection] = None
        self.protocol: base.ProtocolType = protocol
        self.domain: str = domain or ""

        self.clients: Dict[bytes, Connection] = {}

        self.chunk_size: int = chunk_size
        self.bantime: int = base.config.ban_time
        self.max_clients: int = base.config.max_clients
        self.max_connects: int = base.config.max_connects
        self.idle_timeout: int = base.config.idle_timeout
        self.networks: base.IPvXNetworks = base.config.networks or []

        # Total bytes in/out for lost connections
        self.bytes_in: int = 0
        self.bytes_out: int = 0
        self.create_date: datetime = datetime.now()

    def __contains__(self, token: bytes) -> bool:
        return token in self.clients

    def __getitem__(self, token: bytes) -> Connection:
        return self.clients[token]

    @property
    def token(self) -> bytes:
        return self.tunnel.token

    @property
    def uuid(self) -> str:
        return self.tunnel.uuid

    def get_config_dict(self) -> dict:
        """Return the configuration as a dictionary used in the API or client"""
        return {
            "bantime": self.bantime or None,
            "chunk_size": self.chunk_size,
            "idle_timeout": self.idle_timeout or None,
            "max_clients": self.max_clients or None,
            "max_connects": self.max_connects or None,
            "networks": list(map(str, self.networks)) or None,
        }

    def get_state_dict(self) -> dict:
        """Generate a dictionary which shows the current state of the tunnel"""
        tcp, http = [], {}
        if self.protocol == base.ProtocolType.TCP:
            tcp = [{"host": str(host), "port": port} for host, port in self.addr]
        elif self.protocol == base.ProtocolType.HTTP:
            http = {"domain": self.domain}

        clients = {}
        bytes_in, bytes_out = self.bytes_in, self.bytes_out
        for cli in self.clients.values():
            bytes_in += cli.bytes_in
            bytes_out += cli.bytes_out

            clients[cli.uuid] = {
                "create_date": cli.create_date.isoformat(" "),
                "protocol": str(cli.protocol),
                "traffic": {
                    "bytes_in": cli.bytes_in,
                    "bytes_out": cli.bytes_out,
                },
            }

        tun = {"host": self.host, "port": self.port}
        return {
            "address": tun,
            "clients": clients,
            "config": self.get_config_dict(),
            "create_date": self.create_date.isoformat(" "),
            "http": http,
            "protocol": str(self.protocol),
            "tcp": tcp,
            "traffic": {
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
            },
        }

    def info(self, msg: str, *args: Any) -> None:
        _logger.info(f"Tunnel {self.uuid} {msg}", *args)

    def error(self, msg: str, *args: Any) -> None:
        _logger.error(f"Tunnel {self.uuid} {msg}", *args)

    def add(self, client: Connection) -> None:
        if client.token in self.clients:
            return

        if 0 < self.max_clients <= len(self.clients):
            raise base.ReachedClientLimit()

        self.clients[client.token] = client

    def get(self, token: bytes) -> Optional[Connection]:
        return self.clients.get(token, None)

    def pop(self, token: bytes) -> Optional[Connection]:
        return self.clients.pop(token, None)

    def config_from_package(self, pkg: package.ConfigPackage) -> None:
        """Merge the configuration with the current one"""
        self.bantime = utils.merge_settings(self.bantime, pkg.bantime)
        self.max_clients = utils.merge_settings(self.max_clients, pkg.clients)
        self.max_connects = utils.merge_settings(self.max_connects, pkg.connects)
        self.idle_timeout = utils.merge_settings(self.idle_timeout, pkg.idle_timeout)
        self.networks = utils.optimize_networks(*self.networks, *pkg.networks)

        # Just output the current configuration
        networks = self.networks or [ip_network("0.0.0.0/0"), ip_network("::/0")]
        self.info(f"Allowed networks: {', '.join(map(str, networks))}")
        self.info(f"Ban time: {self.bantime or 'off'}")
        self.info(f"Clients: {self.max_clients or '-'}")
        self.info(f"Idle timeout: {self.idle_timeout or 'off'}")
        self.info(f"Connections per IP: {self.max_connects or '-'}")

    async def _disconnect_client(self, token: bytes) -> None:
        """Disconnect a client"""
        client = self.pop(token)
        if client:
            # Store the traffic information from the disconnecting clients
            self.bytes_in += client.bytes_in
            self.bytes_out += client.bytes_out
            _logger.info(f"Client {token.hex()} disconnected")
            await client.close()

    async def idle(self) -> None:
        """This methods will get called regularly to apply timeouts"""
        if self.idle_timeout and self.tunnel:
            if time.time() - self.tunnel.last_time > self.idle_timeout:
                self.info("timeout")
                await self.stop()

    async def stop(self) -> None:
        """Disconnects all clients and stop the tunnel"""
        for client in list(self.clients.values()):
            await client.close()

        if self.tunnel:
            await self.tunnel.close()

    async def _handle(self) -> bool:
        """Basic handler of the tunnel. Return False to leave the main loop"""
        return False

    async def _serve(self) -> None:
        """Main tunnel loop"""
        asyncio.create_task(self._interval())

        while await self._handle():
            pass

    async def _send_config(self) -> None:
        """Send the current configuration as a package through the tunnel"""
        pkg = package.ConfigPackage(
            self.bantime,
            self.max_clients,
            self.max_connects,
            self.idle_timeout,
            self.networks,
        )
        await self.tunnel.tun_write(pkg)

    async def _interval(self) -> None:
        """Calls regularly the idle function"""
        while True:
            await self.idle()
            await asyncio.sleep(base.INTERVAL_TIME)
