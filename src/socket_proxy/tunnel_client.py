import asyncio
import logging
import ssl
import time
from typing import Any, Optional, Sequence, Tuple

from . import api, base, package, tunnel, utils
from .connection import Connection

_logger = logging.getLogger(__name__)


class TunnelClient(tunnel.Tunnel, api.APIMixin):
    """Client side of the tunnel which will connect to a ProxyServer"""

    def __init__(
        self,
        host: str,
        port: int,
        dst_host: str,
        dst_port: int,
        *,
        ca: str,
        cert: Optional[str] = None,
        key: Optional[str] = None,
        auth_token: Optional[str] = None,
        name: Optional[str] = None,
        **kwargs: Any,
    ):
        super().__init__(api_type=api.APIType.Client, **kwargs)

        self.host: str = host
        self.port: int = port
        self.dst_host: str = dst_host
        self.dst_port: int = dst_port
        self.running: bool = False
        self.addr: Sequence[Tuple[base.IPvXAddress, int]] = []
        self.last_ping: float = 0.0
        self.last_pong: float = 0.0
        self.auth_token: Optional[str] = auth_token
        self.name: str = name or ""

        self.bridge_token: Optional[str] = None

        self.ping_enabled: bool = base.config.ping

        self.sc: ssl.SSLContext = utils.generate_ssl_context(
            cert=cert,
            key=key,
            ca=ca,
            check_hostname=not base.config.no_verify_hostname,
        )

    def info(self, msg: str, *args) -> None:
        _logger.info(msg.capitalize(), *args)

    def error(self, msg: str, *args) -> None:
        _logger.error(msg.capitalize(), *args)

    def get_state_dict(self) -> dict:
        state = super().get_state_dict()
        if self.bridge_token:
            state["bridge"] = {
                "token": self.bridge_token,
            }
        return state

    async def idle(self) -> None:
        await super().idle()

        if not self.ping_enabled:
            return

        # Break the connection if the last ping took too long
        if not self._check_alive():
            await self.stop()
            return

        # Send a ping regularly
        self.last_ping = time.time()
        await self.tunnel.tun_write(package.PingPackage(int(self.last_ping)))

    def _check_alive(self) -> bool:
        """Check if the connection is alive using the last ping"""

        if self.last_ping is None or self.last_pong is None:
            return True

        if abs(self.last_pong - self.last_ping) <= base.INTERVAL_TIME:
            return True

        return False

    async def _client_loop(self, client: Connection) -> None:
        """This is the main client loop"""
        self.info(f"Client {client.token.hex()} connected")
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

    async def _connect_client(self, pkg: package.ClientInitPackage) -> None:
        """Handles the connection of a new client through the tunnel"""
        if pkg.token in self:
            return

        try:
            # We have to connect to the specific target
            client = await Connection.connect(self.dst_host, self.dst_port, pkg.token)

            self.add(client)
            asyncio.create_task(self._client_loop(client))
            return
        except Exception:
            self.error("Client connection failed")
            await self.tunnel.tun_write(package.ClientClosePackage(pkg.token))

    async def _send_data(self, pkg: package.ClientDataPackage) -> None:
        """Send data through the tunnel to the server side of the tunnel"""
        client = self.get(pkg.token)
        if client:
            await client.write(pkg.data)

    async def handle_package(self, pkg: package.Package) -> bool:
        """Read a package from the tunnel and handle them properly"""
        # The tunnel was initialized
        if isinstance(pkg, package.InitPackage):
            self.tunnel.token = pkg.token
            self.addr = pkg.addresses
            self.domain = pkg.domain

            # Output the public addresses
            addr = [(base.InternetType.from_ip(ip), ip, port) for ip, port in self.addr]
            for a in sorted(addr):
                self.info(f"open on {utils.format_port(*a)}")

            if self.protocol == base.ProtocolType.HTTP:
                self.info(f"domain: {self.domain}")

            # Send the configuration to the server for negotiation
            await self._send_config()
            return True

        # Information about the server
        if isinstance(pkg, package.InfoPackage):
            self.info(f"Connected with {pkg.name!r} [{pkg.version}]")
            return True

        # The bridge was registered
        if isinstance(pkg, package.BridgeInitPackage):
            self.bridge_token = pkg.token
            self.info(f"Bridge registered: {self.bridge_token}")
            return True

        # Configuration comes back from the server we use that
        if isinstance(pkg, package.ConfigPackage):
            self.config_from_package(pkg)
            return True

        # Handle a ping package and reply
        if isinstance(pkg, package.PingPackage):
            self.last_pong = int(time.time())
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
            self.error(f"invalid package: {pkg}")
            return await super().handle_package(pkg)

        return await super().handle_package(pkg)

    async def disconnect(self, *uuids: str) -> bool:
        """Disconnect a specific client"""
        if len(uuids) < 1:
            return False

        for ctoken, cli in self.clients.items():
            if cli.uuid == uuids[0]:
                await self._disconnect_client(ctoken)
                return True

        return False

    async def loop(self) -> None:
        """Main client loop of the client side of the tunnel"""
        self.tunnel = await Connection.connect(self.host, self.port, ssl=self.sc)
        ssl_obj = self.tunnel.writer.get_extra_info("ssl_object")
        extra = f" [{ssl_obj.version()}]" if ssl_obj else ""
        self.info(f"Tunnel {self.host}:{self.port} connected{extra}")
        self.info(f"Forwarding to {self.dst_host}:{self.dst_port}")

        if self.api_port:
            asyncio.create_task(self.start_api())

        try:
            # Start the tunnel and send the initial package
            self.running = True
            if self.auth_token:
                if base.config.auth_hotp:
                    token = utils.hotp(self.auth_token)
                    pkg = package.AuthPackage(token, base.AuthType.HOTP)
                else:
                    pkg = package.AuthPackage(self.auth_token, base.AuthType.TOTP)

                await self.tunnel.tun_write(pkg)

            await self.tunnel.tun_write(package.ConnectPackage(self.protocol))
            await self.tunnel.tun_write(package.InfoPackage(base.VERSION, self.name))
            await self._serve()
        finally:
            self.running = False
            await self.stop()
            self.info(f"Tunnel {self.host}:{self.port} closed")

    async def start(self) -> None:
        """Start the client and the event loop"""
        self.info("Starting client...")
        await self.loop()
