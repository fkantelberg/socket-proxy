import asyncio
import collections
import ipaddress
import logging
import time
from datetime import datetime, timedelta

from . import base, package, utils
from .config import config
from .connection import Connection

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
        self.info("Allowed networks: %s", ", ".join(map(str, networks)))
        self.info("ban time: %s", self.bantime or "off")
        self.info("clients: %s", self.max_clients or "-")
        self.info("idle timeout: %s", self.idle_timeout or "off")
        self.info("connections per IP: %s", self.max_connects or "-")

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

    async def _serve(self):
        """ Main tunnel loop """
        asyncio.create_task(self._interval())

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
            else:
                # Something unexpected happend
                self.error("invalid package: %s", pkg)
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

    def __init__(
        self, reader, writer, *, domain="", tunnel_host=None, ports=None, **kwargs,
    ):
        super().__init__(**kwargs)
        self.tunnel = Connection(reader, writer, token=utils.generate_token())
        self.domain = f"{self.uuid}.{domain}"
        self.host, self.port = writer.get_extra_info("peername")[:2]
        self.tunnel_host = tunnel_host.split(",") if tunnel_host else ""
        self.ports = ports
        self.server = None
        self.connections = collections.defaultdict(base.Ban)

    def block(self, ip):
        """ Decide whether the ip should be blocked """
        if 0 < self.max_connects <= self.connections[ip].hits:
            return True

        if self.networks and not any(ip in n for n in self.networks):
            return True

        return False

    async def idle(self):
        await super().idle()

        # Clear the connections
        dt = datetime.now() - timedelta(seconds=self.bantime)
        for ip, ban in list(self.connections.items()):
            if ban.first < dt:
                self.connections.pop(ip)
                _logger.info("Connection number of %s resetted", ip)

    async def _client_accept(self, reader, writer, read_ahead=None):
        """ Accept new clients and inform the tunnel about connections """
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

    async def _open_server(self):
        """ Open the public server listener and start the main loop """
        _logger.info("Using protocol: %s", self.protocol.name)

        # Start to listen on an external port
        port = utils.get_unused_port(*self.ports) if self.ports else 0
        if port is None:
            _logger.error("All ports are blocked")
            await self.stop()
            return False

        self.server = await asyncio.start_server(
            self._client_accept, self.tunnel_host, port,
        )
        asyncio.create_task(self._client_loop(self.server))
        return True

    async def _client_loop(self, server):
        """ Main client loop initializing the client and managing the transmission """
        addresses = [sock.getsockname()[:2] for sock in server.sockets]

        # Initialize the tunnel by sending the appropiate data
        out = " ".join(sorted(f"{host}:{port}" for host, port in addresses))
        self.info("listen on %s", out)

        addresses = [(base.InternetType.from_ip(ip), port) for ip, port in addresses]
        pkg = package.InitPackage(self.token, addresses, self.domain)
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
                self.protocol = pkg.protocol

                if self.protocol != base.ProtocolType.TCP:
                    pkg = package.InitPackage(self.token, [], self.domain)
                    await self.tunnel.tun_write(pkg)
                elif not await self._open_server():
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
                self.error("invalid package: %s", pkg)
                break

    async def stop(self):
        """ Stop everything """
        await super().stop()

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        self.info("closed")

    async def loop(self):
        """ Main loop of the proxy tunnel """
        self.info("connected %s:%s", self.host, self.port)

        try:
            await self._serve()
        finally:
            await self.stop()
