import argparse
import hashlib
import ipaddress
import itertools
import logging
import os
import re
import secrets
import socket
import ssl
import sys
from datetime import datetime, timedelta
from random import shuffle
from typing import Any, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlsplit

from . import base

_logger = logging.getLogger(__name__)


class ConfigArgumentParser(argparse.ArgumentParser):
    """Helper class for the configuration management"""

    def _aggregate_actions(
        self, parser: Optional[argparse.ArgumentParser] = None
    ) -> dict:
        result = {}
        for action in (parser or self)._actions:
            if isinstance(action, argparse._SubParsersAction):
                for sub in action.choices.values():
                    result.update(self._aggregate_actions(sub))
            elif action.option_strings:
                result[action.dest] = action
        return result

    def parse_with_config(
        self,
        args: Optional[Sequence[str]] = None,
        config: Optional[dict] = None,
    ) -> argparse.Namespace:
        """Parse the arguments using additional configuration"""
        args = list(sys.argv[1:] if args is None else args[:])

        actions = self._aggregate_actions()

        for key, value in (config or {}).items():
            action = actions.get(key.replace("-", "_"))

            # Skip if it's not a action or if already present in the arguments
            if not action or any(opt in args for opt in action.option_strings):
                continue

            if isinstance(action, argparse._StoreFalseAction):
                if not to_bool(value):
                    args.append(action.option_strings[0])
            elif isinstance(action, argparse._StoreTrueAction):
                if to_bool(value):
                    args.append(action.option_strings[0])
            elif isinstance(action, argparse._StoreConstAction):
                args.append(action.option_strings[0])
            elif isinstance(action, argparse._StoreAction):
                args.extend((action.option_strings[0], str(value)))

        return self.parse_args(args)


class Ban:
    """Helper class for bans"""

    __slots__ = ("first", "hits")

    def __init__(self):
        self.hits = 0
        self.first = datetime.now()


def configure_logging(log_file: str, level_name: str) -> None:
    """Configure the logging"""
    level = base.LOG_LEVELS.get(level_name.lower(), logging.DEBUG)

    log = logging.getLogger()
    log.setLevel(level)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter(base.LOG_FORMAT, style="{"))
    log.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(base.LOG_FORMAT, style="{"))
        log.addHandler(file_handler)


def format_port(ip_type: base.InternetType, ip: base.IPvXAddress, port: int) -> str:
    return f"{'' if ip.is_unspecified else ip}:{port} [{ip_type.name}]"


def format_transfer(b: int) -> str:
    """Format a number of bytes in a more human readable format"""
    symbols = [("T", 1 << 40), ("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)]

    if b < 0:
        raise ValueError("Must be bigger than 0")

    for symbol, size in symbols:
        if b >= size:
            return f"{b / size:.2f} {symbol}"

    return str(b)


def generate_token() -> bytes:
    """Generate a random token used for identification of clients and tunnels"""
    return secrets.token_bytes(base.CLIENT_NAME_SIZE)


def generate_ssl_context(
    *,
    cert: Optional[str] = None,
    key: Optional[str] = None,
    ca: Optional[str] = None,
    crl: Optional[str] = None,
    server: bool = False,
    ciphers: Optional[str] = None,
    check_hostname: bool = False,
) -> ssl.SSLContext:
    """Generate a SSL context for the tunnel"""

    # Set the protocol and create the basic context
    proto = ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT
    ctx = ssl.SSLContext(proto)

    ctx.check_hostname = check_hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Prevent the reuse of parameters
    if server:
        ctx.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE

    # Load a certificate and key for the connection
    if cert:
        ctx.load_cert_chain(cert, keyfile=key)

    # Load the CA to verify the other side
    if ca:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca)

    if crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        ctx.load_verify_locations(cafile=crl)

    # Set possible ciphers to use
    if ciphers:
        ctx.set_ciphers(ciphers)

    # Output debugging
    _logger.info(f"CA usage: {bool(ca)}")
    _logger.info(f"Certificate: {bool(cert)}")
    _logger.info(f"Hostname verification: {bool(check_hostname)}")
    # pylint: disable=no-member
    _logger.info(f"Minimal TLS Version: {ctx.minimum_version.name}")

    used_ciphers = sorted(c["name"] for c in ctx.get_ciphers())
    _logger.info(f"Ciphers: {', '.join(used_ciphers)}")

    return ctx


def get_unused_port(min_port: int, max_port: int, udp: bool = False) -> Optional[int]:
    """Returns a random unused port within the given range or None if all are used"""
    sock = socket.socket(type=socket.SOCK_DGRAM) if udp else socket.socket()
    ports = list(range(min_port, max_port + 1))
    shuffle(ports)
    for port in ports:
        try:
            sock.bind(("", port))
            sock.close()
            return port
        except Exception:
            pass
    return None


def hotp(initial: str, dt: Optional[datetime] = None) -> str:
    """Generate the HOTP token for the specific time. The resolution is 1 min"""
    if dt is None:
        dt = datetime.utcnow()

    base = f"{initial}{dt.replace(second=0, microsecond=0).isoformat(' ')}"
    hashed = hashlib.sha512(base.encode()).hexdigest()

    # Adapt a UUID format
    offsets = [0, 8, 12, 16, 20, 32]
    return "-".join(
        hashed[offsets[i] : offsets[i + 1]] for i in range(len(offsets) - 1)
    )


def hotp_verify(initial: str, token: str, window: int = 5) -> bool:
    """Verify a HOTP token based on a window"""
    dt = datetime.utcnow()
    for i in range(-window, window + 1):
        if token == hotp(initial, dt + timedelta(minutes=i)):
            return True

    return False


def merge_settings(a: int, b: int) -> int:
    """Merge the settings of the tunnel. If one of them is 0 the other one will
    take place. otherwise the lower value will be used"""
    return min(a, b) if a and b else max(a, b)


def optimize_networks(*networks: base.IPvXNetwork) -> base.IPvXNetworks:
    """Try to optimize the list of networks by using the minimal network
    configuration"""

    grouped = itertools.groupby(networks, lambda n: n.version)
    groups = {}
    for version, group in grouped:
        grp = sorted(set(group))
        tmp = set()
        for i, a in enumerate(grp):
            for b in grp[i + 1 :]:
                if b.subnet_of(a):
                    tmp.add(b)
                    break
            else:
                tmp.add(a)
        groups[version] = sorted(tmp)

    return sum([g for _, g in sorted(groups.items())], [])


def parse_address(
    address: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    multiple: bool = False,
) -> Tuple[Union[str, List[str]], int]:
    """Parse an address and split hostname and port. The port is required. The
    default host is "" which means all"""

    # Only the address without scheme and path. We only support IPs if multiple hosts
    # are activated
    pattern = r"[0-9.:\[\],]*?" if multiple else r"[0-9a-zA-Z.:\[\],]*?"
    match = re.match(rf"^(?P<hosts>{pattern})(:(?P<port>\d+))?$", address)
    if not match:
        raise argparse.ArgumentTypeError(
            "Invalid address parsed. Only host and port are supported."
        )

    # Try to parse the port first
    data = match.groupdict()
    if data.get("port"):
        port = int(data["port"])
        if port <= 0 or port >= 65536:
            raise argparse.ArgumentTypeError("Invalid address parsed. Invalid port.")

    if port is None:
        raise argparse.ArgumentTypeError("Port required.")

    # Try parsing the different host addresses
    hosts = set()
    for h in data.get("hosts", "").split(","):
        if not h:
            hosts.add(h or host or "")
            continue

        try:
            parsed = urlsplit(f"http://{h}")
            hosts.add(parsed.hostname)
        except Exception as e:
            raise argparse.ArgumentTypeError(
                "Invalid address parsed. Invalid host."
            ) from e

    # Multiple hosts are supported if the flag is set
    if len(hosts) > 1 and multiple:
        return sorted(hosts), port

    # Otherwise we fail
    if len(hosts) > 1:
        raise argparse.ArgumentTypeError(
            "Invalid address parsed. Only one host is required."
        )

    if len(hosts) == 1:
        host = hosts.pop() or host
        if host is not None:
            return host, port

    raise argparse.ArgumentTypeError("Invalid address parsed. Host required.")


def parse_networks(network: str) -> base.IPvXNetworks:
    """Try to parse multiple networks and return them optimized"""
    try:
        return optimize_networks(*map(ipaddress.ip_network, network.split(",")))
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid network format") from e


def protocols() -> Set[base.ProtocolType]:
    result = set()
    for protocol in base.ProtocolType:
        name = f"no-{protocol.name.lower()}".replace("-", "_")
        if not getattr(base.config, name, False):
            result.add(protocol)

    if not base.config.http_domain:
        result.discard(base.ProtocolType.HTTP)
    return result


def to_bool(val: Any) -> bool:
    if isinstance(val, str):
        return val.lower() in ("true", "t", "1")
    return bool(val)


def traverse_dict(data: dict, *keys: str) -> Any:
    for key in filter(None, keys):
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            raise KeyError()
    return data


def valid_file(path: str) -> str:
    """Check if a file exists and return the absolute path otherwise raise an
    error. This function is used for the argument parsing"""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError("Not a file.")
    return path


def valid_ports(ports: str) -> Tuple[int, int]:
    """Check if the argument is a valid port range with IP family"""
    m = re.match(r"^(\d+):(\d+)?$", ports, re.IGNORECASE)
    if m:
        a, b = sorted(map(int, m.groups()))
        if 0 < a < b < 65536:
            return a, b
        raise argparse.ArgumentTypeError("Port must be in range (1, 65536)")
    raise argparse.ArgumentTypeError("Invalid port scheme.")


def valid_token(token: str) -> str:
    """Check if the token is valid. Any alphanumeric token or UUID are allowed"""
    if not re.fullmatch(r"[a-zA-Z0-9-]+", token):
        raise argparse.ArgumentTypeError("Invalid token format [a-zA-Z0-9-]+")
    return token
