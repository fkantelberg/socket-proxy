import asyncio
import logging
import time
from typing import TypeVar

from . import base, package

_logger = logging.getLogger(__name__)


class Connection:
    """ Wrapper class to handle StreamReader and StreamWriter """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: base.ProtocolType = base.ProtocolType.TCP,
        token: bytes = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.reader, self.writer = reader, writer
        self.protocol = protocol
        self.token = token or b""
        self.bytes_in = self.bytes_out = 0
        self.last_time = time.time()

    @property
    def uuid(self) -> str:
        return self.token.hex()

    @classmethod
    async def connect(
        cls, host: str, port: int, token: bytes = None, **kwargs,
    ) -> TypeVar("Connection"):
        streams = await asyncio.open_connection(host, port, **kwargs)
        return cls(*streams, token=token)

    async def tun_data(self, token: bytes, data: bytes) -> None:
        """ Write data packages on the tunnel and chunk them """
        if len(token) != base.CLIENT_NAME_SIZE:
            raise base.InvalidPackage()

        pkg = package.ClientDataPackage(data, token)
        self.write(pkg.to_bytes())
        await self.drain()

    async def close(self) -> None:
        try:
            self.reader.feed_eof()
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def tun_read(self) -> package.Package:
        return await package.Package.from_reader(self)

    async def tun_write(self, pkg: package.Package) -> None:
        self.write(pkg.to_bytes())
        await self.drain()

    async def readexactly(self, size: int) -> bytes:
        data = await self.reader.readexactly(size)
        self.bytes_in += size
        self.last_time = time.time()
        return data

    async def read(self, size: int) -> bytes:
        data = await self.reader.read(size)
        self.bytes_in += len(data)
        self.last_time = time.time()
        return data

    def write(self, data: bytes) -> None:
        self.bytes_out += len(data)
        self.last_time = time.time()
        self.writer.write(data)

    async def drain(self) -> None:
        await self.writer.drain()
