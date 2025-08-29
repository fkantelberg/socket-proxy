import ipaddress
import logging
import struct
from typing import Any, Dict, Optional, Tuple

from . import base

try:
    from typing import Protocol, Self
except ImportError:
    from typing_extensions import Protocol, Self  # type: ignore


_logger = logging.getLogger(__name__)
_package_registry: Dict[int, "MetaPackage"] = {}


class Reader(Protocol):
    """Protocol to read data from a reader"""

    async def readexactly(self, length: int) -> bytes: ...


class MetaPackage(type):
    """Meta class to register new packages using the type"""

    def __new__(metacls, name, bases, attrs):
        ptype = attrs.get("_type", None)
        if ptype and ptype in _package_registry:
            raise base.DuplicatePackageType()

        cls = super().__new__(metacls, name, bases, attrs)
        if ptype is not None:
            _package_registry[ptype] = cls
        return cls


class PackageStruct(struct.Struct):
    """Helper class to read exactly the size of the structure from the
    StreamReader and unpacking it properly"""

    @classmethod
    def pack_network(cls, network: base.IPvXNetwork) -> bytes:
        ip = network.network_address
        ip_type = base.InternetType.from_ip(ip)
        return struct.pack("!BB", ip_type, network.prefixlen) + ip.packed

    @classmethod
    def pack_string(cls, value: str) -> bytes:
        bvalue = value.encode()
        return struct.pack("!I", len(value)) + bvalue

    async def read(self, reader: Reader) -> Tuple[Any, ...]:
        return self.unpack(await reader.readexactly(self.size))

    @classmethod
    async def read_network(cls, reader: Reader) -> base.IPvXNetwork:
        ip_type, prefixlen = await cls("!BB").read(reader)
        ip = await PackageStruct.read_ip(ip_type, reader)
        return ipaddress.ip_network(f"{ip}/{prefixlen}")

    @classmethod
    async def read_ip(
        cls, ip_type: base.InternetType, reader: Reader
    ) -> base.IPvXAddress:
        if ip_type == base.InternetType.IPv4:
            return ipaddress.IPv4Address(await reader.readexactly(4))

        if ip_type == base.InternetType.IPv6:
            return ipaddress.IPv6Address(await reader.readexactly(16))

        raise base.InvalidPackageType()

    @classmethod
    async def read_string(cls, reader: Reader) -> str:
        (length,) = await cls("!I").read(reader)
        return (await reader.readexactly(length)).decode() if length else ""


class Package(metaclass=MetaPackage):
    """Base package which defines the package type. Building a package is done
    by the unique package type and class inheritance.

    Structure: <package type>
    """

    _name: Optional[str] = None
    _type: int = 0x00
    __slots__: Tuple[str, ...] = ()

    HEADER = PackageStruct("!B")

    def to_bytes(self) -> bytes:
        """Transform a package to bytes"""
        return self.HEADER.pack(self._type)

    def __repr__(self) -> str:
        return f"<Package [{self._name}]>"

    # pylint: disable=W0613
    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        """Read the package from the reader and return a tuple. The tuple is
        getting passed to the constructor"""
        return ()

    @classmethod
    async def from_reader(cls, reader: Reader) -> Optional[Self]:
        """Read the package type and enforce the building of the package"""
        try:
            (ptype,) = await cls.HEADER.read(reader)

            if ptype not in _package_registry:
                raise base.InvalidPackageType(str(ptype))

            pcls = _package_registry[ptype]
            return pcls(*await pcls.recv(reader))
        except Exception:
            return None


class ConnectPackage(Package):
    """Package to configure/start the server site of an expose server

    Structure: <SUPER> <protocol>
    """

    _name: Optional[str] = "connect"
    _type: int = 0x01
    __slots__: Tuple[str, ...] = ("protocol",)

    PROTOCOL = PackageStruct("!B")

    def __init__(self, protocol: base.ProtocolType, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = protocol

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.PROTOCOL.pack(self.protocol.value)

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        (protocol,) = await cls.PROTOCOL.read(reader)
        return (base.ProtocolType(protocol),) + res


class PingPackage(Package):
    """Package to for a regular ping to keep the connection active

    Structure: <SUPER> <time>
    """

    _name: Optional[str] = "ping"
    _type: int = 0x02
    __slots__: Tuple[str, ...] = ("time",)

    TIMESTAMP = PackageStruct("!d")

    def __init__(self, timestamp: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.time: int = timestamp

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.TIMESTAMP.pack(self.time)

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        return await cls.TIMESTAMP.read(reader) + res


class AuthPackage(Package):
    """Package to for a regular ping to keep the connection active

    Structure: <SUPER> <length of token> <token> <token type>
    """

    _name: Optional[str] = "auth"
    _type: int = 0x03
    __slots__: Tuple[str, ...] = ("token", "token_type")

    def __init__(self, token: str, token_type: base.AuthType, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token: str = token
        self.token_type: base.AuthType = token_type

    def to_bytes(self) -> bytes:
        return (
            super().to_bytes()
            + PackageStruct.pack_string(self.token)
            + PackageStruct("!B").pack(self.token_type)
        )

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        token = await PackageStruct.read_string(reader)
        (token_type,) = await PackageStruct("!B").read(reader)
        return (token, base.AuthType(token_type)) + res


class InfoPackage(Package):
    """Package to exchange some information about the own side

    Structure: <SUPER> <version> <name>
    """

    _name: Optional[str] = "info"
    _type: int = 0x04
    __slots__: Tuple[str, ...] = ("version", "name")

    def __init__(self, version: str, name: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.name = name

    def to_bytes(self) -> bytes:
        return (
            super().to_bytes()
            + PackageStruct.pack_string(self.version)
            + PackageStruct.pack_string(self.name)
        )

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        version = await PackageStruct.read_string(reader)
        name = await PackageStruct.read_string(reader)
        return (version, name) + res


class ExposePackage(Package):
    """Pseudo package for expose servers to structure the package classes"""


class InitPackage(ExposePackage):
    """Package to initialize the tunnel which sends the external port. The number of
    addresses is limitted to 255

    Structure: <SUPER> <tunnel token> <number of ports>
               (<type of port> <external port>)* <length of domain> <domain>
    """

    _name: Optional[str] = "expose>init"
    _type: int = 0x10
    __slots__: Tuple[str, ...] = ("token", "addresses", "domain")

    INIT = PackageStruct(f"!{base.CLIENT_NAME_SIZE}sB")
    ADDRESS = PackageStruct("!BH")

    def __init__(
        self,
        token: bytes,
        addresses: base.IPvXPorts,
        domain: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.token: bytes = token
        self.addresses: base.IPvXPorts = addresses[:255]
        self.domain: str = domain

    def to_bytes(self) -> bytes:
        data = super().to_bytes() + self.INIT.pack(self.token, len(self.addresses))
        for ip, port in self.addresses:
            if isinstance(ip, str):
                ip = ipaddress.ip_address(ip)

            ip_type = base.InternetType.from_ip(ip)
            data += self.ADDRESS.pack(ip_type, port) + ip.packed
        return data + PackageStruct.pack_string(self.domain)

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        token, length = await cls.INIT.read(reader)
        addresses = []
        for _ in range(length):
            ip_type, port = await cls.ADDRESS.read(reader)
            ip_type = base.InternetType(ip_type)
            if ip_type == base.InternetType.IPv4:
                ip = await reader.readexactly(4)
            elif ip_type == base.InternetType.IPv6:
                ip = await reader.readexactly(16)
            else:
                continue

            addresses.append((ipaddress.ip_address(ip), port))

        domain = await PackageStruct.read_string(reader)
        return (token, addresses, domain) + res


class BridgePackage(Package):
    """Pseudo package for bridge servers to structure the package classes"""


class BridgeInitPackage(BridgePackage):
    """Package to initialize the tunnel which sends the token to connect to the
    bridge

    Structure: <SUPER> <length of token> <token>
    """

    _name: Optional[str] = "bridge>init"
    _type: int = 0x21
    __slots__: Tuple[str, ...] = ("token",)

    def __init__(self, token: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token: str = token

    def to_bytes(self) -> bytes:
        return super().to_bytes() + PackageStruct.pack_string(self.token)

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        token = await PackageStruct.read_string(reader)
        return (token,) + res


class BridgeLinkPackage(BridgeInitPackage):
    """Package to link to a bridge using the shared token

    Structure: <SUPER> <length of token> <token>
    """

    _name: Optional[str] = "bridge>link"
    _type: int = 0x22


class ConfigPackage(Package):
    """Package to inform about configurations. This package will be send between
    both sides of the tunnel to negotiate the configuration by using the minimum
    from each side or the maximum if one of the configuration is 0

    Structure: <SUPER> <config> <length of networks> <networks>
    """

    _name: Optional[str] = "config"
    _type: int = 0x11
    __slots__: Tuple[str, ...] = (
        "bantime",
        "clients",
        "connects",
        "idle_timeout",
        "networks",
    )

    CONFIG = PackageStruct("!IIIII")

    def __init__(
        self,
        bantime: int,
        clients: int,
        connects: int,
        idle_timeout: int,
        networks: base.IPvXNetworks,
        *args,
        **kwargs,
    ):  # pylint: disable=R0917
        super().__init__(*args, **kwargs)
        self.bantime: int = bantime
        self.clients: int = clients
        self.connects: int = connects
        self.idle_timeout: int = idle_timeout
        self.networks: base.IPvXNetworks = networks

    def to_bytes(self) -> bytes:
        config = self.CONFIG.pack(
            self.bantime,
            self.clients,
            self.connects,
            self.idle_timeout,
            len(self.networks),
        )
        networks = b"".join(map(PackageStruct.pack_network, self.networks))
        return super().to_bytes() + config + networks

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        config = list(await cls.CONFIG.read(reader))
        config[-1] = [
            await PackageStruct.read_network(reader) for _ in range(config[-1])
        ]
        return tuple(config) + res


class ClientPackage(Package):
    """Basic client package which adds an unique token for the tunnel to determine
    the specific clients

    Structure: <SUPER> <client token>
    """

    _name: Optional[str] = "client"
    _type: int = 0x30
    __slots__: Tuple[str, ...] = ("token",)

    TOKEN = PackageStruct(f"!{base.CLIENT_NAME_SIZE}s")

    def __init__(self, token: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token: bytes = token

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.TOKEN.pack(self.token)

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        return await cls.TOKEN.read(reader) + res


class ClientInitPackage(ClientPackage):
    """Package to initialize a connecting client sending the client information

    Structure: <SUPER> <ip type> <client port> <client ip>
    """

    _name: Optional[str] = "client>init"
    _type: int = 0x31
    __slots__: Tuple[str, ...] = ("ip", "port")

    IP = PackageStruct("!BH")

    def __init__(self, ip: base.IPvXAddress, port: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip: base.IPvXAddress = ip
        self.port: int = port

    def to_bytes(self) -> bytes:
        ip_type: base.InternetType = base.InternetType.from_ip(self.ip)
        return super().to_bytes() + self.IP.pack(ip_type, self.port) + self.ip.packed

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        ip_type, port = await cls.IP.read(reader)
        ip = await PackageStruct.read_ip(ip_type, reader)
        return (ip, port) + res


class ClientClosePackage(ClientPackage):
    """Package to inform the other side about a disconnected client

    Structure: <SUPER>
    """

    _name: Optional[str] = "client>close"
    _type: int = 0x32
    __slots__: Tuple[str, ...] = ()


class ClientDataPackage(ClientPackage):
    """Package to transmit data through the tunnel. This will produce quite some
    overhead for many smaller packages

    Structure: <SUPER> <data length> <data>
    """

    _name: Optional[str] = "client>data"
    _type: int = 0x33
    __slots__: Tuple[str, ...] = ("data",)

    MAX_SIZE = 65536
    DATA = PackageStruct("!I")

    def __init__(self, data: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data: bytes = data

    def to_bytes(self) -> bytes:
        data = b""
        header = super().to_bytes()
        for i in range(0, len(self.data), self.MAX_SIZE):
            chunk = self.data[i:][: self.MAX_SIZE]
            data += header + self.DATA.pack(len(chunk)) + chunk
        return data

    @classmethod
    async def recv(cls, reader: Reader) -> Tuple[Any, ...]:
        res = await super().recv(reader)
        (length,) = await cls.DATA.read(reader)
        if length > cls.MAX_SIZE:
            raise base.InvalidPackage()

        data = await reader.readexactly(length)
        return (data,) + res
