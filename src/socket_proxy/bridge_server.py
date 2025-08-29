import asyncio
from asyncio import StreamReader, StreamWriter
from typing import Dict, Optional, Tuple

from . import base, package, tunnel, utils
from .connection import Connection
from .event import EventSystem


class BridgeServer(tunnel.Tunnel):
    """Server side of the tunnel to listen for external connections"""

    def __init__(
        self,
        *,
        reader: Optional[StreamReader] = None,
        writer: Optional[StreamWriter] = None,
        tunnel: Optional[Connection] = None,
        event: EventSystem,
        **kwargs,
    ):
        super().__init__(**kwargs)

        self.tunnel: Connection
        if reader and writer:
            self.host, self.port = writer.get_extra_info("peername")[:2]
            self.tunnel = Connection(reader, writer)
        elif tunnel:
            self.host, self.port = tunnel.get_extra_info("peername")[:2]
            self.tunnel = tunnel
        else:
            raise base.NoConnection()

        self.event: EventSystem = event
        # Mapping of the bridge tokens and the client tokens
        self.downstream: Dict[Tuple[bytes, bytes], Optional[bytes]] = {}
        self.upstream: Dict[bytes, Optional[Tuple[bytes, bytes]]] = {}

    async def idle(self) -> None:
        await super().idle()

        # Clean the downstream mappings
        for down_key, down_value in list(self.downstream.items()):
            if not down_value:
                self.downstream.pop(down_key)

        # Clean the upstream mappings
        for up_key, up_value in list(self.upstream.items()):
            if not up_value:
                self.upstream.pop(up_key)

    async def _handle_client_upstream(
        self,
        pkg: package.Package,
        bridge: Connection,
    ) -> bool:
        """Handle packages coming from the bridge"""
        if isinstance(pkg, package.InfoPackage):
            self.info(f"Connected with {pkg.name!r} on {bridge.uuid} [{pkg.version}]")
            return True

        if isinstance(pkg, package.ExposePackage):
            return True

        if not isinstance(pkg, package.ClientPackage):
            self.warning(f"Unexpected package on {bridge.uuid}: {pkg}")
            return False

        client_token = self.downstream.get((bridge.token, pkg.token))
        if not client_token and not isinstance(
            pkg, (package.ClientClosePackage, package.ClientInitPackage)
        ):
            self.warning(f"Unexpected package on {bridge.uuid}: {pkg}")
            return False

        if not client_token:
            # New connection means new mapping
            client_token = utils.generate_token()
            self.downstream[bridge.token, pkg.token] = client_token
            self.upstream[client_token] = (bridge.token, pkg.token)
            self.info(f"New client on bridge {bridge.uuid}")
            await self.event.send(msg="client_connect")

        if isinstance(pkg, package.ClientClosePackage):
            # Remove the client from the mappings
            self.downstream[bridge.token, pkg.token] = None
            self.upstream[client_token] = None
            self.info(f"Closed client on bridge {bridge.uuid}")
            await self.event.send(msg="client_disconnect")

        # Replace the token and pass the package upstream
        pkg.token = client_token
        await self.tunnel.tun_write(pkg)
        return True

    async def _handle_client_downstream(self, pkg: package.ClientPackage) -> bool:
        """Handle packages going to the bridge"""
        tokens = self.upstream.get(pkg.token)
        if not tokens:
            # Client was disconnected
            return True

        bridge = self.get(tokens[0])
        if not bridge:
            return False

        if isinstance(pkg, package.ClientClosePackage):
            self.upstream[pkg.token] = None
            self.downstream[tokens] = None
            self.info(f"Closed client on bridge {bridge.uuid}")
            await self.event.send(msg="client_disconnect")

        # Replace the token and pass the package downstream
        pkg.token = tokens[1]
        await bridge.tun_write(pkg)
        return True

    async def _handle_client(self, bridge: Connection) -> bool:
        """Basic handler on the bridge connections"""
        pkg = await bridge.tun_read()
        if not pkg:
            return False

        return await self._handle_client_upstream(pkg, bridge)

    async def handle_package(self, pkg: package.Package) -> bool:
        """Handle packages coming from the bridge"""
        if isinstance(pkg, (package.ExposePackage, package.InfoPackage)):
            return True

        if isinstance(pkg, package.ConnectPackage):
            self.info("Bridge registered")
            await self.tunnel.tun_write(package.BridgeInitPackage(self.uuid))
            return True

        if isinstance(pkg, package.BridgeLinkPackage):
            return True

        if isinstance(pkg, package.ConfigPackage):
            self.config_from_package(pkg)
            await self._send_config()
            return True

        # Handle a ping package and reply
        if isinstance(pkg, package.PingPackage):
            await self.tunnel.tun_write(pkg)
            return True

        # Handle a client packages
        if isinstance(pkg, package.ClientPackage):
            return await self._handle_client_downstream(pkg)

        # Invalid package means to close the connection
        return await super().handle_package(pkg)

    async def _bridge_loop(self, bridge: Connection) -> None:
        """This is the main client loop"""
        self.info(f"Bridge {bridge.uuid} connected")
        await self.event.send(msg="bridge_added")
        try:
            await bridge.tun_write(package.ConnectPackage(base.ProtocolType.TCP))

            while await self._handle_client(bridge):
                pass
        finally:
            await self._disconnect_client(bridge.token)
            self.info(f"Bridge {bridge.uuid} disconnected")

    async def _disconnect_client(self, token: bytes) -> None:
        """Remove the clients from the bridge and send ClientClosePackage"""
        for down_tokens, client_token in list(self.downstream.items()):
            if client_token and down_tokens[0] == token:
                self.downstream[down_tokens] = None
                await self.tunnel.tun_write(package.ClientClosePackage(client_token))

        for key, tokens in list(self.upstream.items()):
            if tokens and tokens[0] == token:
                self.upstream[key] = None

        return await super()._disconnect_client(token)

    async def add_bridge(self, bridge: Connection) -> bool:
        """Add a new bridge and start the bridge loop"""
        try:
            self.add(bridge)
            asyncio.create_task(self._bridge_loop(bridge))
            self.info("Bridge task started")
            return True
        except Exception:
            self.error("Bridge connection failed")
            return False

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
        """Main loop of the proxy tunnel"""
        ssl_obj = self.tunnel.writer.get_extra_info("ssl_object")
        extra = f" [{ssl_obj.version()}]" if ssl_obj else ""
        self.info(f"Connected {self.host}:{self.port}{extra}")

        try:
            await self._serve()
        finally:
            await self.stop()
