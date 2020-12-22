import enum
import ipaddress
import logging
from datetime import datetime

_logger = logging.getLogger(__name__)

CLIENT_NAME_SIZE = 8
INTERVAL_TIME = 1
DEFAULT_PORT = 2773
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


class InvalidPackage(Exception):
    """ Generic exception for package specific exceptions """


class InvalidPackageType(InvalidPackage):
    """ The package type is unknown """


class DuplicatePackageType(InvalidPackage):
    """ The package types aren't unique between all registered packages """


class ReachedClientLimit(Exception):
    """ The tunnel reached the maximum number of simultanous clients connected """


class InternetType(enum.IntEnum):
    """ Helper for IP addresses and identification """

    IPv4 = 0x01
    IPv6 = 0x02

    @staticmethod
    def from_ip(ip):
        if isinstance(ip, (bytes, str)):
            ip = ipaddress.ip_address(ip)

        if isinstance(ip, ipaddress.IPv4Address):
            return InternetType.IPv4
        if isinstance(ip, ipaddress.IPv6Address):
            return InternetType.IPv6
        raise ipaddress.AddressValueError()


class ProtocolType(enum.IntEnum):
    """ Helper class for supported protocols """

    TCP = 0x01


class Ban:
    """ Helper class for bans """

    __slots__ = ("first", "hits")

    def __init__(self):
        self.hits = 0
        self.first = datetime.now()
