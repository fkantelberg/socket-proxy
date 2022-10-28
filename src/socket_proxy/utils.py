import argparse
import ipaddress
import itertools
import logging
import os
import re
import secrets
import socket
import ssl
import sys
from datetime import datetime
from random import shuffle
from typing import Any, List, Set, Tuple, Union
from urllib.parse import urlsplit

from . import base

_logger = logging.getLogger(__name__)


class ConfigArgumentParser(argparse.ArgumentParser):
    """Helper class for the configuration management"""

    def _aggregate_actions(self, parser=None) -> dict:
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
        args: Tuple[str] = None,
        config: dict = None,
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


def configure_logging(log_file: str, level: str) -> None:
    """Configure the logging"""
    level = base.LOG_LEVELS.get(level.lower(), logging.DEBUG)

    log = logging.getLogger()
    log.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(base.LOG_FORMAT, style="{"))
    log.addHandler(handler)

    if log_file:
        handler = logging.FileHandler(log_file)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(base.LOG_FORMAT, style="{"))
        log.addHandler(handler)


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
    cert: str = None,
    key: str = None,
    ca: str = None,
    crl: str = None,
    server: bool = False,
    ciphers: List[str] = None,
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
    _logger.info("CA usage: %s", bool(ca))
    _logger.info("Certificate: %s", bool(cert))
    _logger.info("Hostname verification: %s", bool(check_hostname))
    # pylint: disable=no-member
    _logger.info("Minimal TLS Version: %s", ctx.minimum_version.name)

    ciphers = sorted(c["name"] for c in ctx.get_ciphers())
    _logger.info("Ciphers: %s", ", ".join(ciphers))

    return ctx


def get_unused_port(min_port: int, max_port: int, udp: bool = False) -> int:
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


def merge_settings(a: int, b: int) -> int:
    """Merge the settings of the tunnel. If one of them is 0 the other one will
    take place. otherwise the lower value will be used"""
    return min(a, b) if a and b else max(a, b)


def optimize_networks(*networks: List[base.IPvXNetwork]) -> List[base.IPvXNetwork]:
    """Try to optimize the list of networks by using the minimal network
    configuration"""

    grouped = itertools.groupby(networks, lambda n: n.version)
    groups = {}
    for version, group in grouped:
        group = sorted(set(group))
        tmp = set()
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if b.subnet_of(a):
                    tmp.add(b)
                    break
            else:
                tmp.add(a)
        groups[version] = sorted(tmp)

    return sum([g for _, g in sorted(groups.items())], [])


def parse_address(
    address: str, host: str = None, port: int = None, multiple: bool = False
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
            hosts.add(h or host)
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


def parse_networks(network: str) -> List[base.IPvXNetwork]:
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


def traverse_dict(data: dict, *keys: Tuple[str]) -> Any:
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


def valid_ports(ports: Tuple[int, int]) -> Tuple[int, int]:
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
