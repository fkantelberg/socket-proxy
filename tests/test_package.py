import asyncio
import ipaddress

import pytest
from socket_proxy import base, package


def test_meta_package():
    with pytest.raises(base.DuplicatePackageType):

        class DuplicatePackage(package.Package):
            _name = "duplicate"
            _type = package.InitPackage._type

        assert not DuplicatePackage

    class TestPackage(package.Package):
        _name = "test"
        _type = 1024

    assert issubclass(TestPackage, package.Package)
    assert package._package_registry[1024] == TestPackage


@pytest.mark.asyncio
async def test_network_packing():
    net4, net6 = map(ipaddress.ip_network, ("127.0.0.0/8", "ff::/32"))
    packed4, packed6 = map(package.PackageStruct.pack_network, (net4, net6))

    assert packed4 == b"\x01\x08\x7f\x00\x00\x00"
    assert packed6 == b"\x02\x20\x00\xff" + b"\x00" * 14

    reader = asyncio.StreamReader()
    reader.feed_data(packed4)
    reader.feed_data(packed6)
    reader.feed_data(b"\x00\x00")
    reader.feed_eof()

    assert await package.PackageStruct.read_network(reader) == net4
    assert await package.PackageStruct.read_network(reader) == net6

    with pytest.raises(base.InvalidPackage):
        await package.PackageStruct.read_network(reader)


@pytest.mark.asyncio
async def test_invalid_ip_type():
    token = b"\x00" * base.CLIENT_NAME_SIZE
    reader = asyncio.StreamReader()
    reader.feed_data(b"\x31%s\x00\x00\x00" % token)
    reader.feed_eof()

    await asyncio.sleep(0.1)
    with pytest.raises(base.InvalidPackageType):
        await package.ClientInitPackage.recv(reader)


@pytest.mark.asyncio
async def test_invalid_package_type():
    reader = asyncio.StreamReader()
    reader.feed_data(b"\xff")
    reader.feed_eof()

    assert await package.Package.from_reader(reader) is None


@pytest.mark.asyncio
async def test_invalid_client_data_length():
    token = b"\x00" * base.CLIENT_NAME_SIZE
    reader = asyncio.StreamReader()
    reader.feed_data(b"\x31%s\xff\xff\xff\xff" % token)
    reader.feed_eof()

    with pytest.raises(base.InvalidPackage):
        await package.ClientDataPackage.recv(reader)
