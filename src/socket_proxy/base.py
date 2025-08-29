import argparse
import enum
import ipaddress
import logging
import os
from datetime import datetime
from typing import Any, Optional, Sequence, Tuple

_logger = logging.getLogger(__name__)

VERSION = "6.0.0"

CLIENT_NAME_SIZE = 8
EVENT_TIMEOUT = 0.5
INTERVAL_TIME = 1
DEFAULT_PORT = 2773
DEFAULT_API_PORT = 7773
DEFAULT_HTTP_PORT = 8773
DEFAULT_LOG_LEVEL = "info"
LOG_FORMAT = "{asctime} [{levelname:^8}] {message}"

LOG_LEVELS = {
    "critical": logging.CRITICAL,
    "debug": logging.DEBUG,
    "error": logging.ERROR,
    "info": logging.INFO,
    "warn": logging.WARN,
    "warning": logging.WARNING,
}

IPvXAddress = ipaddress._BaseAddress
IPvXNetwork = ipaddress._BaseNetwork
IPvXPort = Tuple[ipaddress._BaseAddress, int]
IPvXAddresses = Sequence[ipaddress._BaseAddress]
IPvXNetworks = Sequence[ipaddress._BaseNetwork]
IPvXPorts = Sequence[IPvXPort]


class InvalidPackage(Exception):
    """Generic exception for package specific exceptions"""


class InvalidPackageType(InvalidPackage):
    """The package type is unknown"""


class DuplicatePackageType(InvalidPackage):
    """The package types aren't unique between all registered packages"""


class ReachedClientLimit(Exception):
    """The tunnel reached the maximum number of simultanous clients connected"""


class NoConnection(Exception):
    """Raised when a server can't build the connection properly"""


class AuthType(enum.IntEnum):
    """Helper for authentication token types"""

    TOTP = 0x01
    HOTP = 0x02

    def __str__(self) -> str:
        return {AuthType.TOTP: "totp", AuthType.HOTP: "hotp"}.get(self, "")


class AuthToken:
    """Helper for authentication tokens"""

    def __init__(self, dt: Optional[datetime] = None):
        if not dt:
            self.creation = datetime.now()
        elif isinstance(dt, str):
            self.creation = datetime.fromisoformat(dt)
        else:
            self.creation = dt


class InternetType(enum.IntEnum):
    """Helper for IP addresses and identification"""

    IPv4 = 0x01
    IPv6 = 0x02

    @classmethod
    def from_ip(cls, ip: IPvXAddress) -> Any:
        if isinstance(ip, (bytes, str)):
            ip = ipaddress.ip_address(ip)

        if isinstance(ip, ipaddress.IPv4Address):
            return InternetType.IPv4
        if isinstance(ip, ipaddress.IPv6Address):
            return InternetType.IPv6
        raise ipaddress.AddressValueError()

    def localhost(self):
        return {
            InternetType.IPv4: "127.0.0.1",
            InternetType.IPv6: "::1",
        }[self]


class ProtocolType(enum.IntEnum):
    """Helper class for supported protocols"""

    TCP = 0x01
    HTTP = 0x02
    BRIDGE = 0x11

    def __str__(self) -> str:
        return {
            ProtocolType.TCP: "TCP",
            ProtocolType.HTTP: "HTTP",
            ProtocolType.BRIDGE: "BRIDGE",
        }[self]

    @classmethod
    def from_str(cls, protocol: str) -> Any:
        if protocol.upper() == "TCP":
            return cls.TCP
        if protocol.upper() == "HTTP":
            return cls.HTTP
        if protocol.upper() == "BRIDGE":
            return cls.BRIDGE
        raise ValueError("Invalid protocol")


config = argparse.Namespace(
    api=False,
    api_listen=("::1", DEFAULT_API_PORT),
    api_ssl=False,
    api_token=None,
    authentication=False,
    auth_hotp=False,
    auth_timeout=900,
    auth_token=None,
    ban_time=60,
    bridge=None,
    ca=None,
    cert=None,
    cipher=None,
    crl=None,
    connect=None,
    dst=None,
    http_domain=None,
    http_listen=("", DEFAULT_HTTP_PORT),
    http_ssl=False,
    hook_token=None,
    hook_url=None,
    idle_timeout=0,
    key=None,
    listen=("", DEFAULT_PORT),
    log_file=None,
    log_level=DEFAULT_LOG_LEVEL,
    max_clients=0,
    max_connects=0,
    max_tunnels=0,
    mode=None,
    networks=[],
    no_curses="TERM" not in os.environ,
    no_server=False,
    no_verify_hostname=False,
    persist_state=None,
    ping=False,
    ports=None,
    protocol=ProtocolType.TCP,
    tunnel_host=None,
    version=False,
)
