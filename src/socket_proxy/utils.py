import argparse
import logging
import os
import re
import secrets
import socket
import ssl
import sys
from random import shuffle
from urllib.parse import urlsplit

from . import base

_logger = logging.getLogger(__name__)


def configure_logging(log_file, level):
    """ Configure the logging """
    level = base.LOG_LEVELS.get(level.lower(), logging.DEBUG)

    log = logging.getLogger()
    log.setLevel(level)
    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(base.LOG_FORMAT, style="{"))
    log.addHandler(handler)


def generate_token():
    """ Generate a random token used for identification of clients and tunnels """
    return secrets.token_bytes(base.CLIENT_NAME_SIZE)


def generate_ssl_context(
    *, cert=None, key=None, ca=None, server=False, ciphers=None, check_hostname=False,
):
    """ Generate a SSL context for the tunnel """

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

    # Set possible ciphers to use
    if ciphers:
        ctx.set_ciphers(ciphers)

    # Output debugging
    _logger.debug("CA usage: %s", bool(ca))
    _logger.debug("Certificate: %s", bool(cert))
    _logger.debug("Hostname verification: %s", bool(check_hostname))
    _logger.debug("Minimal TLS Versions: %s", ctx.minimum_version.name)

    ciphers = sorted(c["name"] for c in ctx.get_ciphers())
    _logger.debug("Ciphers: %s", ", ".join(ciphers))

    return ctx


def get_unused_port(min_port, max_port, udp=False):
    """ Returns a random unused port within the given range or None if all are used """
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


def merge_settings(a, b):
    """ Merge the settings of the tunnel. If one of them is 0 the other one will
        take place. otherwise the lower value will be used """
    return min(a, b) if a and b else max(a, b)


def parse_address(address, host=None, port=None, multiple=False):
    """ Parse an address and split hostname and port. The port is required. The
        default host is "" which means all """

    # Only the address without scheme and path. We only support IPs if multiple hosts
    # are activated
    pattern = r"[0-9.:\[\],]*?" if multiple else r"[0-9a-zA-Z.:\[\],]*?"
    match = re.match(fr"^(?P<hosts>{pattern})(:(?P<port>\d+))?$", address)
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
        except Exception:
            raise argparse.ArgumentTypeError("Invalid address parsed. Invalid host.")

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


def valid_file(path):
    """ Check if a file exists and return the absolute path otherwise raise an
        error. This function is used for the argument parsing"""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError("Not a file.")
    return path


def valid_ports(ports):
    """ Check if the argument is a valid port range with IP family """
    m = re.match(r"^(\d+):(\d+)?$", ports, re.IGNORECASE)
    if m:
        a, b = map(int, m.groups())
        if 0 < a < b < 65536:
            return a, b
        raise argparse.ArgumentTypeError("Port must be in range (1, 65536)")
    raise argparse.ArgumentTypeError("Invalid port scheme.")
