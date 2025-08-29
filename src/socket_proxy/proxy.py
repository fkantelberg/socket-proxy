import asyncio
import json
import logging
import re
import ssl
import uuid
from asyncio import StreamReader, StreamWriter
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Union

from . import api, base, event, package, utils
from .bridge_server import BridgeServer
from .connection import Connection
from .expose_server import ExposeServer

_logger = logging.getLogger(__name__)

HTTPRequestStatus = re.compile(rb"^(\S+)\s+(\S+)\s+(\S+)$")


class ProxyServer(api.APIMixin):
    """Main proxy server which creates a TLS socket and listens for clients.
    If clients connect the server will start a BridgeServer or ExposeServer"""

    def __init__(
        self,
        host: Union[str, List[str]],
        port: int,
        *,
        cert: str,
        key: str,
        ca: Optional[str] = None,
        crl: Optional[str] = None,
        authentication: bool = False,
        auth_timeout: int = 60,
        protocols: Optional[List[base.ProtocolType]] = None,
        **kwargs: Any,
    ):
        super().__init__(api_type=api.APIType.Server)
        self.expose_kwargs: Dict[str, Any] = kwargs
        self.host: Union[str, List[str]] = host
        self.port: int = port
        self.max_tunnels: int = base.config.max_tunnels
        self.http_ssl: bool = base.config.http_ssl

        self.sc: ssl.SSLContext = utils.generate_ssl_context(
            cert=cert,
            key=key,
            ca=ca,
            crl=crl,
            server=True,
        )

        # Tunnels
        self.expose_servers: Dict[str, ExposeServer] = {}
        self.bridge_servers: Dict[str, BridgeServer] = {}

        # Protocols
        self.protocols: List[base.ProtocolType] = protocols or utils.protocols()

        # Authentication
        self.authentication: bool = authentication
        self.tokens: Dict[base.AuthType, dict] = defaultdict(dict)
        self.auth_timeout: int = auth_timeout

        self.event: event.EventSystem = event.EventSystem(
            event.EventType.Server,
            url=getattr(base.config, "hook_url", None),
            token=getattr(base.config, "hook_token", None),
        )

        self.http_domain: str = ""
        self.http_host: Optional[str] = None
        self.http_port: Optional[str] = None
        self.http_domain_regex: Optional[re.Pattern] = None
        if isinstance(base.config.http_domain, str) and base.config.http_listen:
            self.http_host, self.http_port = base.config.http_listen
            self.http_domain = base.config.http_domain
            self.http_domain_regex = re.compile(
                rb"^(.*)\.%s$" % self.http_domain.replace(".", r"\.").encode()
            )

        self._load_persisted_state()

    def _load_persisted_state(self, file: Optional[str] = None) -> None:
        """Load the previously persisted state from the file"""
        file = file or base.config.persist_state
        if not file:
            return

        try:
            with open(file, encoding="utf-8") as fp:
                state = json.load(fp)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        # Restore the tokens
        self.tokens.clear()

        # Stay compatible
        for token, dt in state.get("tokens", {}).items():
            ttype = base.AuthType.TOTP if dt else base.AuthType.HOTP
            self.tokens[ttype][token] = base.AuthToken(dt)

        for auth_type in base.AuthType:
            for token, creation in state.get(f"tokens_{auth_type}", {}).items():
                self.tokens[auth_type][token] = base.AuthToken(creation)

    def _save_persisted_state(self, file: Optional[str] = None) -> None:
        """Persist the internal state of the proxy server like tokens"""
        file = file or base.config.persist_state
        if not file:
            return

        state = self.get_persistant_state_dict()
        with open(file, "w+", encoding="utf-8") as fp:
            json.dump(state, fp)

    async def idle(self) -> None:
        """This methods will get called regularly to apply timeouts"""
        dt = datetime.now() - timedelta(seconds=self.auth_timeout)
        changes = False
        for token, t in list(self.tokens[base.AuthType.TOTP].items()):
            if t.creation < dt:
                self.tokens[base.AuthType.TOTP].pop(token, None)
                changes = True
                _logger.info(f"Invalidated token {token}")
                await self.event.send(msg="token_invalidate", token=token)

        if self.authentication and not self.tokens[base.AuthType.TOTP]:
            self.generate_token()
        elif changes:
            self._save_persisted_state()

        # Flush the event queue
        await self.event.flush()

    def generate_token(self, hotp: bool = False) -> Optional[str]:
        """Generate a new authentication token"""
        if not self.authentication:
            return None

        token = str(uuid.uuid4())
        auth_type = base.AuthType.HOTP if hotp else base.AuthType.TOTP
        self.tokens[auth_type][token] = base.AuthToken()

        _logger.info(f"Generated authentication token {token} [{auth_type}]")
        self.event.send_nowait(msg="token_generate", token=token, hotp=bool(hotp))
        self._save_persisted_state()
        return token

    async def _api_handle(self, path: Sequence[str], request: api.Request) -> Any:
        """Handle api functions"""
        if ("token", "hotp") == path[:2]:
            return self.generate_token(True)
        if "token" in path[:1]:
            return self.generate_token(False)
        return await super()._api_handle(path, request)

    def _verify_auth_token(self, pkg: package.AuthPackage) -> bool:
        """Verify an authentication package"""
        if pkg.token_type == base.AuthType.TOTP:
            return pkg.token in self.tokens[base.AuthType.TOTP]

        if pkg.token_type == base.AuthType.HOTP:
            return any(
                utils.hotp_verify(token, pkg.token)
                for token in self.tokens[base.AuthType.HOTP]
            )

        return False

    async def _accept(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Accept new tunnels and start to listen for clients"""
        # pylint: disable=R0912

        # Limit the number of tunnels
        if 0 < self.max_tunnels <= len(self.expose_servers):
            await self.close(reader, writer)
            return

        tunnel = Connection(reader, writer)
        if self.authentication:
            # Expect the token as first package
            pkg = await tunnel.tun_read()
            if not isinstance(pkg, package.AuthPackage):
                await self.close(reader, writer)
                return

            if not self._verify_auth_token(pkg):
                await self.close(reader, writer)
                return

        # First package decides the type of the server
        server: Optional[Union[BridgeServer, ExposeServer]]

        pkg = await tunnel.tun_read()
        if isinstance(pkg, package.BridgeLinkPackage):
            server = self.bridge_servers.get(pkg.token)
            if not server:
                await self.close(reader, writer)
                return

            if not await server.add_bridge(tunnel):
                await self.close(reader, writer)

            return

        if isinstance(pkg, package.ConnectPackage):
            if pkg.protocol not in self.protocols:
                _logger.error(f"Disabled protocol {pkg.protocol.name}")
                await self.close(reader, writer)
                return

            if pkg.protocol == base.ProtocolType.BRIDGE:
                server = BridgeServer(
                    tunnel=tunnel,
                    event=self.event,
                )
                self.bridge_servers[server.uuid] = server
            else:
                server = ExposeServer(
                    tunnel=tunnel,
                    event=self.event,
                    domain=self.http_domain,
                    **self.expose_kwargs,
                )
                self.expose_servers[server.uuid] = server

        else:
            # Unexpected package
            await self.close(reader, writer)
            return

        # Server is connected after the first package was handled correctly
        if not await server.handle_package(pkg):
            await self.close(reader, writer)
            self.expose_servers.pop(server.uuid, None)
            self.bridge_servers.pop(server.uuid, None)
            return

        await self.event.send(msg="server_connect", tunnel=server.uuid)
        try:
            await server.loop()
        finally:
            await self.event.send(msg="server_disconnect", tunnel=server.uuid)
            _logger.info(f"Close server {server.uuid}")
            self.expose_servers.pop(server.uuid, None)
            self.bridge_servers.pop(server.uuid, None)

    async def _request(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Handle http requests and try to proxy them to the specific tunnel"""
        buf = await reader.readline()
        status = buf.strip()
        match = HTTPRequestStatus.match(status)
        if not match:
            await self.close(reader, writer)
            return

        version = match.groups()[2]

        # Read the HTTP headers
        headers = {}
        while not reader.at_eof():
            line = await reader.readline()
            buf += line

            stripped = line.strip()
            if not stripped:
                break

            if b":" in stripped:
                header, value = (x.strip() for x in stripped.split(b":", 1))
                headers[header.lower()] = value

        # Extract the host from the headers and try matching them
        host = headers.get(b"x-forwarded-host", headers.get(b"host", b""))
        match = self.http_domain_regex.match(host)
        if not match or len(match.groups()) < 1:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)
            return

        # Find the right tunnel for the host
        tun_uuid = match.groups()[0].decode()
        if tun_uuid not in self.expose_servers:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)
            return

        # Get the tunnel and accept the client if set to HTTP protocol
        tunnel = self.expose_servers[tun_uuid]
        if tunnel.protocol == base.ProtocolType.HTTP:
            await tunnel._client_accept(reader, writer, buf)
        else:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)

    async def http_loop(self) -> None:
        """Main server loop for the http socket"""
        host = self.http_host
        for h in host if isinstance(host, list) else [host]:
            _logger.info(f"Serving on {h}:{self.http_port} [HTTP]")

        self.http_proxy = await asyncio.start_server(
            self._request,
            self.http_host,
            self.http_port,
            ssl=self.sc if self.http_ssl else None,
        )

        async with self.http_proxy:
            await self.http_proxy.serve_forever()

    async def loop(self) -> None:
        """Main server loop to wait for tunnels to open"""
        if self.http_domain_regex:
            asyncio.create_task(self.http_loop())
            await self.event.send(msg="http_start")

        if self.api_port:
            asyncio.create_task(self.start_api())
            await self.event.send(msg="api_start")

        asyncio.create_task(self._interval())

        self.server = await asyncio.start_server(
            self._accept,
            self.host,  # type: ignore
            self.port,
            ssl=self.sc,
        )

        for host in self.host if isinstance(self.host, list) else [self.host]:
            _logger.info(f"Serving on {host}:{self.port}")

        await self.event.send(msg="proxy_start")

        async with self.server:
            await self.server.serve_forever()

    def get_persistant_state_dict(self) -> dict:
        """Generate a dictionary with all persistance information"""
        return {
            f"tokens_{t}": {
                token: t.creation.isoformat(" ") for token, t in self.tokens[t].items()
            }
            for t in base.AuthType
        }

    def get_state_dict(self) -> dict:
        """Generate a dictionary which shows the current state of the server"""
        state = self.get_persistant_state_dict()
        # Stay compatible
        state["tokens"] = {
            **state["tokens_totp"],
            **dict.fromkeys(state["tokens_hotp"], None),
        }
        return {
            **state,
            "http": {
                "domain": self.http_domain,
                "host": self.http_host,
                "port": self.http_port,
            }
            if self.http_domain
            else {},
            "tcp": {
                "host": self.host,
                "port": self.port,
            },
            "exposes": {
                tuuid: tunnel.get_state_dict()
                for tuuid, tunnel in self.expose_servers.items()
            },
            "bridges": {
                tuuid: tunnel.get_state_dict()
                for tuuid, tunnel in self.bridge_servers.items()
            },
        }

    async def disconnect(self, *uuids: str) -> bool:
        """Disconnect a specific tunnel or client"""
        if len(uuids) < 1 or uuids[0] not in self.expose_servers:
            return False

        tunnel = self.expose_servers[uuids[0]]
        if len(uuids) == 1:
            await tunnel.stop()
            return True

        for ctoken, cli in tunnel.clients.items():
            if cli.uuid == uuids[1]:
                await tunnel._disconnect_client(ctoken)
                return True

        return False

    async def start(self) -> None:
        """Start the server and event loop"""
        _logger.info("Starting server...")
        await self.loop()

    async def stop(self) -> None:
        """Stop the server and event loop"""
        for tunnel in self.expose_servers.values():
            await tunnel.stop()

        if self.api:
            await self.api.cleanup()
            await self.api.shutdown()

        self.server.close()
        await self.server.wait_closed()

    async def close(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Close a StreamReader and StreamWriter"""
        reader.feed_eof()
        writer.close()
        await writer.wait_closed()

    async def _interval(self) -> None:
        """Calls regularly the idle function"""
        while True:
            await self.idle()
            await asyncio.sleep(base.INTERVAL_TIME)
