import asyncio
import collections
import ipaddress
import logging
import time
from datetime import datetime, timedelta

from . import base, package, utils
from .connection import Connection

_logger = logging.getLogger(__name__)


class Tunnel:
    """ Generic implementation of the tunnel """

    def __init__(
        self,
        *,
        protocol=base.ProtocolType.TCP,
        bantime=60,
        chunk_size=65536,
        max_clients=0,
        max_connects=0,
        idle_timeout=0,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.tunnel = None
        self.clients = {}
        self.protocol = protocol
        self.bantime = bantime
        self.chunk_size = chunk_size
        self.max_clients = max_clients
        self.max_connects = max_connects
        self.idle_timeout = idle_timeout

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

        # Just output the current configuration for debugging
        _logger.debug("Tunnel %s ban time: %s", self.uuid, self.bantime or "off")
        _logger.debug("Tunnel %s clients: %s", self.uuid, self.max_clients or "off")
        _logger.debug(
            "Tunnel %s idle timeout: %s", self.uuid, self.idle_timeout or "off"
        )
        _logger.debug(
            "Tunnel %s connections per IP: %s", self.uuid, self.max_connects or "off",
        )

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
                _logger.info("Tunnel %s timeout", self.uuid)
                await self.stop()

    async def stop(self):
        """ Disconnects all clients and stop the tunnel """
        for client in list(self.clients.values()):
            await client.close()

        if self.tunnel:
            await self.tunnel.close()

    async def _serve(self):
        """ Main tunnel loop """
        asyncio.create_task(self._interval())

    async def _send_config(self):
        """ Send the current configuration as a package through the tunnel """
        pkg = package.ConfigPackage(
            self.bantime, self.max_clients, self.max_connects, self.idle_timeout,
        )
        await self.tunnel.tun_write(pkg)

    async def _interval(self):
        """ Calls regularly the idle function """
        while True:
            await self.idle()
            await asyncio.sleep(base.INTERVAL_TIME)


class TunnelClient(Tunnel):
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

                # Output the public addresses
                for ip_type, port in sorted(self.addresses):
                    _logger.info(
                        "Tunnel %s open: %s on port %s",
                        self.tunnel.uuid,
                        ip_type.name,
                        port,
                    )

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
            else:
                # Something unexpected happend
                _logger.error("Invalid package: %s", pkg)
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


class TunnelServer(Tunnel):
    """ Server side of the tunnel to listen for external connections """

    def __init__(self, reader, writer, *, tunnel_host=None, ports=None, **kwargs):
        super().__init__(**kwargs)
        self.tunnel = Connection(reader, writer, token=utils.generate_token())
        self.host, self.port = writer.get_extra_info("peername")[:2]
        self.tunnel_host = tunnel_host.split(",") if tunnel_host else ""
        self.ports = ports
        self.server = None
        self.connections = collections.defaultdict(base.Ban)

    async def idle(self):
        await super().idle()

        # Clear the connections
        dt = datetime.now() - timedelta(seconds=self.bantime)
        for ip, ban in list(self.connections.items()):
            if ban.first < dt:
                self.connections.pop(ip)
                _logger.info("Connection number of %s resetted", ip)

    async def _client_accept(self, reader, writer):
        """ Accept new clients and inform the tunnel about connections """
        host, port = writer.get_extra_info("peername")[:2]
        ip = ipaddress.ip_address(host)

        # If the IP exceeds the maximum number of connections
        if 0 < self.max_connects <= self.connections[ip].hits:
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

        # Serve data from the client
        while True:
            data = await client.read(self.chunk_size)
            # Client disconnected. Inform the tunnel
            if not data:
                break

            await self.tunnel.tun_data(client.token, data)

        if self.server.is_serving():
            pkg = package.ClientClosePackage(client.token)
            await self.tunnel.tun_write(pkg)

        await self._disconnect_client(client.token)

    async def _open_server(self, pkg):
        """ Open the public server listener and start the main loop """

        self.protocol = pkg.protocol
        _logger.info("Using protocol: %s", self.protocol.name)

        # Start to listen on an external port
        port = utils.get_unused_port(*self.ports) if self.ports else 0
        if port is None:
            _logger.error("All ports are blocked")
            await self.stop()
            return False

        _logger.error("%s: %s [%s]", self.tunnel_host, port, self.ports)

        self.server = await asyncio.start_server(
            self._client_accept, self.tunnel_host, port
        )
        asyncio.create_task(self._client_loop(self.server))
        return True

    async def _client_loop(self, server):
        """ Main client loop initializing the client and managing the transmission """
        addresses = [sock.getsockname()[:2] for sock in server.sockets]

        # Initialize the tunnel by sending the appropiate data
        out = " ".join(sorted(f"{host}:{port}" for host, port in addresses))
        _logger.info("Tunnel %s listen on %s", self.uuid, out)

        addresses = [(base.InternetType.from_ip(ip), port) for ip, port in addresses]
        pkg = package.InitPackage(self.token, addresses)
        await self.tunnel.tun_write(pkg)

        # Start listening
        async with server:
            await server.serve_forever()

    async def _serve(self):
        """ Listen on the tunnel """
        await super()._serve()

        while True:
            pkg = await self.tunnel.tun_read()
            # Start the server
            if isinstance(pkg, package.ConnectPackage):
                if not await self._open_server(pkg):
                    break
            # Handle configuration
            elif isinstance(pkg, package.ConfigPackage):
                self.config_from_package(pkg)
                await self._send_config()
            # Handle a closed client
            elif isinstance(pkg, package.ClientClosePackage):
                await self._disconnect_client(pkg.token)
            # Handle data coming through the tunnel
            elif isinstance(pkg, package.ClientDataPackage):
                # Check for valid tokens
                if pkg.token not in self:
                    _logger.error("Invalid client token: %s", pkg.token)
                    break

                conn = self[pkg.token]
                conn.write(pkg.data)
                await conn.drain()
            # Invalid package means to close the connection
            else:
                _logger.error("Invalid package: %s", pkg)
                break

    async def stop(self):
        """ Stop everything """
        await super().stop()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        _logger.info("Tunnel %s closed", self.uuid)

    async def loop(self):
        """ Main loop of the proxy tunnel """
        _logger.info(
            "Tunnel %s connected %s:%s", self.uuid, self.host, self.port,
        )

        try:
            await self._serve()
        finally:
            await self.stop()
