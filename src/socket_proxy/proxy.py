import asyncio
import json
import logging
import re
import uuid
from asyncio import StreamReader, StreamWriter
from datetime import datetime, timedelta
from typing import Any, List, Tuple, Union

from . import api, base, event, package, utils
from .tunnel_server import TunnelServer

_logger = logging.getLogger(__name__)

HTTPRequestStatus = re.compile(rb"^(\S+)\s+(\S+)\s+(\S+)$")


class ProxyServer(api.APIMixin):
    """Main proxy server which creates a TLS socket and listens for clients.
    If clients connect the server will start a TunnelServer"""

    def __init__(
        self,
        host: Union[str, List[str]],
        port: int,
        cert: str,
        key: str,
        ca: str = None,
        crl: str = None,
        authentication: bool = False,
        auth_timeout: int = 60,
        **kwargs,
    ):
        super().__init__(api_type=api.APIType.Server)
        self.kwargs = kwargs
        self.host, self.port = host, port
        self.max_tunnels = base.config.max_tunnels
        self.http_ssl = base.config.http_ssl
        self.tunnels = {}
        self.tokens = {}
        self.sc = utils.generate_ssl_context(
            cert=cert,
            key=key,
            ca=ca,
            crl=crl,
            server=True,
        )
        self.http_proxy = self.server = None

        self.authentication = authentication
        self.auth_timeout = auth_timeout
        self.event = event.EventSystem(
            event.EventType.Server,
            url=base.config.hook_url,
            token=base.config.hook_token,
        )

        if isinstance(base.config.http_domain, str) and base.config.http_listen:
            self.http_host, self.http_port = base.config.http_listen
            self.http_domain = base.config.http_domain
            self.http_domain_regex = re.compile(
                rb"^(.*)\.%s$" % self.http_domain.replace(".", r"\.").encode()
            )
        else:
            self.http_host = self.http_port = False
            self.http_domain = self.http_domain_regex = False

        self._load_persisted_state()

    def _load_persisted_state(self, file: str = None) -> None:
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
        for tkn, dt in state.get("tokens", {}).items():
            self.tokens[tkn] = datetime.fromisoformat(dt) if dt else None

    def _persist_state(self, file: str = None) -> None:
        """Persist the internal state of the proxy server like tokens"""
        file = file or base.config.persist_state
        if not file:
            return

        with open(file, "w+", encoding="utf-8") as fp:
            json.dump(
                {
                    "tokens": {
                        tkn: dt.isoformat(" ") if dt else dt
                        for tkn, dt in self.tokens.items()
                    }
                },
                fp,
            )

    async def idle(self) -> None:
        """This methods will get called regularly to apply timeouts"""
        dt = datetime.now() - timedelta(seconds=self.auth_timeout)
        changes = False
        for token, t in list(self.tokens.items()):
            if t and token and t < dt:
                self.tokens.pop(token, None)
                changes = True
                _logger.info(f"Invalidated token {token}")
                await self.event.send(msg="token_invalidate", token=token)

        if self.authentication and not self.tokens:
            self.generate_token()
        elif changes:
            self._persist_state()

        # Flush the event queue
        await self.event.flush()

    def generate_token(self, hotp: bool = False) -> str:
        """Generate a new authentication token"""
        if not self.authentication:
            return None

        token = str(uuid.uuid4())
        self.tokens[token] = None if hotp else datetime.now()
        ttype = "hotp" if hotp else "totp"
        _logger.info(f"Generated authentication token {token} [{ttype}]")
        self.event.send_nowait(msg="token_generate", token=token, hotp=bool(hotp))
        self._persist_state()
        return token

    async def _api_handle(self, path: Tuple[str], request: api.Request) -> Any:
        """Handle api functions"""
        if ("token", "hotp") == path[:2]:
            return self.generate_token(True)
        if "token" in path[:1]:
            return self.generate_token(False)
        return await super()._api_handle(path, request)

    def _verify_auth_token(self, pkg: package.AuthPackage) -> bool:
        """Verify an authentication package"""
        if pkg.token_type == base.AuthType.TOTP:
            return pkg.token in {tk for tk, dt in self.tokens.items() if dt}

        if pkg.token_type == base.AuthType.HOTP:
            for token, dt in self.tokens.items():
                if dt is None and utils.hotp_verify(token, pkg.token):
                    return True

        return False

    async def _accept(self, reader: StreamReader, writer: StreamWriter) -> None:
        """Accept new tunnels and start to listen for clients"""

        # Limit the number of tunnels
        if 0 < self.max_tunnels <= len(self.tunnels):
            await self.close(reader, writer)
            return

        # Create the tunnel object and generate an unique token
        tunnel = TunnelServer(
            reader,
            writer,
            event=self.event,
            domain=self.http_domain,
            **self.kwargs,
        )

        if self.authentication:
            # Expect the token as first package
            pkg = await tunnel.tunnel.tun_read()
            if not isinstance(pkg, package.AuthPackage):
                await self.close(reader, writer)
                return

            if not self._verify_auth_token(pkg):
                await self.close(reader, writer)
                return

        self.tunnels[tunnel.uuid] = tunnel
        await self.event.send(msg="tunnel_connect", tunnel=tunnel.uuid)
        try:
            await tunnel.loop()
        finally:
            await self.event.send(msg="tunnel_disconnect", tunnel=tunnel.uuid)
            self.tunnels.pop(tunnel.uuid)

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
        if tun_uuid not in self.tunnels:
            writer.write(b"%s 404 Not Found\r\n\r\n" % version)
            await writer.drain()
            await self.close(reader, writer)
            return

        # Get the tunnel and accept the client if set to HTTP protocol
        tunnel = self.tunnels[tun_uuid]
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
            self.host,
            self.port,
            ssl=self.sc,
        )

        for host in self.host if isinstance(self.host, list) else [self.host]:
            _logger.info(f"Serving on {host}:{self.port}")

        await self.event.send(msg="proxy_start")

        async with self.server:
            await self.server.serve_forever()

    def get_state_dict(self) -> dict:
        """Generate a dictionary which shows the current state of the server"""
        tunnels = {}
        for tuuid, tunnel in self.tunnels.items():
            tunnels[tuuid] = tunnel.get_state_dict()

        http = {
            "domain": self.http_domain,
            "host": self.http_host,
            "port": self.http_port,
        }

        return {
            "http": http if self.http_domain else {},
            "tcp": {
                "host": self.host,
                "port": self.port,
            },
            "tokens": {
                t: dt.isoformat(" ") if dt else dt for t, dt in self.tokens.items()
            },
            "tunnels": tunnels,
        }

    async def disconnect(self, *uuids: Tuple[str]) -> bool:
        """Disconnect a specific tunnel or client"""
        if len(uuids) < 1 or uuids[0] not in self.tunnels:
            return False

        tunnel = self.tunnels[uuids[0]]
        if len(uuids) == 1:
            await tunnel.stop()
            return True

        for ctoken, cli in tunnel.clients.items():
            if cli.uuid == uuids[1]:
                await tunnel._disconnect_client(ctoken)
                return True

        return False

    def start(self) -> None:
        """Start the server and event loop"""
        _logger.info("Starting server...")
        asyncio.run(self.loop())

    async def stop(self) -> None:
        """Stop the server and event loop"""
        for tunnel in self.tunnels.values():
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
