import asyncio
import logging
import time

from . import base, package

_logger = logging.getLogger(__name__)


# Wrapper class to handle StreamReader and StreamWriter
class Connection:
    def __init__(self, reader, writer, token=None, **kwargs):
        super().__init__(**kwargs)
        self.reader, self.writer = reader, writer
        self.token = token or b""
        self.bytes_in = self.bytes_out = 0
        self.last_time = time.time()

    @property
    def uuid(self):
        return self.token.hex()

    @classmethod
    async def connect(cls, host, port, token=None, **kwargs):
        streams = await asyncio.open_connection(host, port, **kwargs)
        return cls(*streams, token=token)

    # Write data packages on the tunnel and chunk them
    async def tun_data(self, token, data):
        if len(token) != base.CLIENT_NAME_SIZE:
            raise base.InvalidPackage()

        chunk_size = package.ClientDataPackage.MAX_SIZE
        for i in range(0, len(data), chunk_size):
            chunk = data[i:][:chunk_size]
            pkg = package.ClientDataPackage(chunk, token)
            self.write(pkg.to_bytes())
            await self.drain()

    async def close(self):
        try:
            self.reader.feed_eof()
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def tun_read(self):
        return await package.Package.from_reader(self)

    async def tun_write(self, pkg):
        self.write(pkg.to_bytes())
        await self.drain()

    async def readexactly(self, size):
        data = await self.reader.readexactly(size)
        self.bytes_in += size
        self.last_time = time.time()
        return data

    async def read(self, size):
        data = await self.reader.read(size)
        self.bytes_in += len(data)
        self.last_time = time.time()
        return data

    def write(self, data):
        self.bytes_out += len(data)
        self.last_time = time.time()
        return self.writer.write(data)

    async def drain(self):
        return await self.writer.drain()
