import asyncio
import logging
import time
from datetime import datetime
from typing import Optional

from . import base, package

try:
    from typing import Self
except ImportError:
    from typing_extensions import Self


_logger = logging.getLogger(__name__)


class Connection:
    """Wrapper class to handle StreamReader and StreamWriter"""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: base.ProtocolType = base.ProtocolType.TCP,
        token: Optional[bytes] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.reader, self.writer = reader, writer
        self.protocol: base.ProtocolType = protocol
        self.token: bytes = token or b""
        self.bytes_in: int = 0
        self.bytes_out: int = 0
        self.create_date: datetime = datetime.now()
        self.last_time: float = time.time()

    @property
    def uuid(self) -> str:
        return self.token.hex()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        token: Optional[bytes] = None,
        **kwargs,
    ) -> Self:
        streams = await asyncio.open_connection(host, port, **kwargs)
        return cls(*streams, token=token)

    async def tun_data(self, token: bytes, data: bytes) -> None:
        """Write data packages on the tunnel and chunk them"""
        if len(token) != base.CLIENT_NAME_SIZE:
            raise base.InvalidPackage()

        pkg = package.ClientDataPackage(data, token)
        await self.write(pkg.to_bytes())

    async def close(self) -> None:
        try:
            self.reader.feed_eof()
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def tun_read(self) -> Optional[package.Package]:
        return await package.Package.from_reader(self)

    async def tun_write(self, pkg: package.Package) -> None:
        await self.write(pkg.to_bytes())

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

    async def write(self, data: bytes) -> None:
        self.bytes_out += len(data)
        self.last_time = time.time()
        self.writer.write(data)
        await self.writer.drain()
