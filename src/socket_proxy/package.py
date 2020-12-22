import ipaddress
import logging
import struct

from . import base

_logger = logging.getLogger(__name__)
_package_registry = {}


class MetaPackage(type):
    """ Meta class to register new packages using the type """

    def __new__(metacls, name, bases, attrs):
        ptype = attrs["_type"]
        if ptype in _package_registry:
            raise base.DuplicatePackageType()

        cls = super().__new__(metacls, name, bases, attrs)
        if ptype is not None:
            _package_registry[ptype] = cls
        return cls


class PackageStruct(struct.Struct):
    """ Helper class to read exactly the size of the structure from the
        StreamReader and unpacking it properly """

    async def read(self, reader):
        return self.unpack(await reader.readexactly(self.size))


class Package(metaclass=MetaPackage):
    """ Base package which defines the package type. Building a package is done
        by the unique package type and class inheritance.

        Structure: <package type>
    """

    _name = None
    _type = None
    __slots__ = ()

    HEADER = PackageStruct("!B")

    def to_bytes(self):
        """ Transform a package to bytes """
        return self.HEADER.pack(self._type)

    @classmethod
    async def recv(cls, reader):  # pylint: disable=W0613
        """ Read the package from the reader and return a tuple. The tuple is
            getting passed to the constructor """
        return ()

    @classmethod
    async def from_reader(cls, reader):
        """ Read the package type and enforce the building of the package """
        try:
            (ptype,) = await cls.HEADER.read(reader)

            if ptype not in _package_registry:
                raise base.InvalidPackageType()

            pcls = _package_registry[ptype]
            return pcls(*await pcls.recv(reader))
        except Exception:
            return None


class ConnectPackage(Package):
    """ Package to configure/start the server site

        Structure: <SUPER>
    """

    _name = "connect"
    _type = 0x01
    __slots__ = ("protocol",)

    PROTOCOL = PackageStruct("!B")

    def __init__(self, protocol, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.protocol = protocol

    def to_bytes(self):
        return super().to_bytes() + self.PROTOCOL.pack(self.protocol.value)

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        (protocol,) = await cls.PROTOCOL.read(reader)
        return (base.ProtocolType(protocol),) + res


class InitPackage(Package):
    """ Package to initialize the tunnel which sends the external port. The number of
        addresses is limitted to 255

        Structure: <SUPER> <tunnel token> <number of ports> (<type of port> <external port>)*
    """

    _name = "init"
    _type = 0x10
    __slots__ = ("token", "addresses")

    INIT = PackageStruct(f"!{base.CLIENT_NAME_SIZE}sB")
    ADDRESS = PackageStruct("!BH")

    def __init__(self, token, addresses, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = token
        self.addresses = addresses[:255]

    def to_bytes(self):
        data = super().to_bytes() + self.INIT.pack(self.token, len(self.addresses))
        for address in self.addresses:
            data += self.ADDRESS.pack(*address)
        return data

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        token, length = await cls.INIT.read(reader)
        addresses = []
        for _ in range(length):
            ip_type, port = await cls.ADDRESS.read(reader)
            addresses.append((base.InternetType(ip_type), port))

        return (token, addresses) + res


class ConfigPackage(Package):
    """ Package to inform about configurations. This package will be send between
        both sides of the tunnel to negotiate the configuration by using the minimum
        from each side or the maximum if one of the configuration is 0

        Structure: <SUPER> <connects>
    """

    _name = "client>config"
    _type = 0x11
    __slots__ = ("bantime", "clients", "connects", "idle_timeout")

    CONFIG = PackageStruct("!IIII")

    def __init__(self, bantime, clients, connects, idle_timeout, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bantime = bantime
        self.clients = clients
        self.connects = connects
        self.idle_timeout = idle_timeout

    def to_bytes(self):
        return super().to_bytes() + self.CONFIG.pack(
            self.bantime, self.clients, self.connects, self.idle_timeout,
        )

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        return await cls.CONFIG.read(reader) + res


class ClientPackage(Package):
    """ Basic client package which adds an unique token for the tunnel to determine
        the specific clients

        Structure: <SUPER> <client token>
    """

    _name = "client"
    _type = 0x30
    __slots__ = ("token",)

    TOKEN = PackageStruct(f"!{base.CLIENT_NAME_SIZE}s")

    def __init__(self, token, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = token

    def to_bytes(self):
        return super().to_bytes() + self.TOKEN.pack(self.token)

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        return await cls.TOKEN.read(reader) + res


class ClientInitPackage(ClientPackage):
    """ Package to initialize a connecting client sending the client information

        Structure: <SUPER> <ip type> <client port> <client ip>
    """

    _name = "client>init"
    _type = 0x31
    __slots__ = ("ip", "port")

    IP = PackageStruct("!BH")

    def __init__(self, ip, port, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip, self.port = ip, port

    def to_bytes(self):
        ip_type = base.InternetType.from_ip(self.ip)
        return super().to_bytes() + self.IP.pack(ip_type, self.port) + self.ip.packed

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        ip_type, port = await cls.IP.read(reader)
        if ip_type == base.InternetType.IPv4:
            ip = ipaddress.IPv4Address(await reader.readexactly(4))
        elif ip_type == base.InternetType.IPv6:
            ip = ipaddress.IPv6Address(await reader.readexactly(16))
        else:
            raise base.InvalidPackageType()
        return (ip, port) + res


class ClientClosePackage(ClientPackage):
    """ Package to inform the other side about a disconnected client

        Structure: <SUPER>
    """

    _name = "client>close"
    _type = 0x32
    __slots__ = ()


class ClientDataPackage(ClientPackage):
    """ Package to transmit data through the tunnel. This will produce quite some
        overhead for many smaller packages

        Structure: <SUPER> <data length> <data>
    """

    _name = "client>data"
    _type = 0x33
    __slots__ = ("data",)

    MAX_SIZE = 65536
    DATA = PackageStruct("!I")

    def __init__(self, data, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = data

    def to_bytes(self):
        data = b""
        header = super().to_bytes()
        for i in range(0, len(self.data), self.MAX_SIZE):
            chunk = self.data[i:][: self.MAX_SIZE]
            data += header + self.DATA.pack(len(chunk)) + chunk
        return data

    @classmethod
    async def recv(cls, reader):
        res = await super().recv(reader)
        (length,) = await cls.DATA.read(reader)
        if length > cls.MAX_SIZE:
            raise base.InvalidPackage()

        data = await reader.read(length)
        return (data,) + res
