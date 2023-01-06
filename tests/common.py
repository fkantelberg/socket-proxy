import subprocess

from socket_proxy import utils

CA_CERT = "pki/ca.pem"
CLIENT_CERT = "pki/client.pem"
CLIENT_KEY = "pki/client.key"
SERVER_CERT = "pki/server.pem"
SERVER_KEY = "pki/server.key"
CRL = "pki/crl.pem"

TCP_PORT = utils.get_unused_port(5000, 10000)
TCP_PORT_DUMMY = utils.get_unused_port(5000, 10000)

with subprocess.Popen(["./certs.sh", "client"], stdin=subprocess.PIPE) as proc:
    proc.communicate()
with subprocess.Popen(["./certs.sh", "server"], stdin=subprocess.PIPE) as proc:
    proc.communicate(b"y\n" * 80)


# pylint: disable=W0613


def raiseAssertAsync(*args, **kwargs):
    raise AssertionError()
