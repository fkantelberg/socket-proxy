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


# Generate a random token used for identification of clients and tunnels
def generate_token():
    return secrets.token_bytes(base.CLIENT_NAME_SIZE)


# Generate a SSL context for the tunnel
def generate_ssl_context(
    *, cert=None, key=None, ca=None, server=False, ciphers=None, check_hostname=False,
):
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


# Returns a random unused port within the given range or None if all are used
def get_unused_port(min_port, max_port):
    sock = socket.socket()
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


# Merge the settings of the tunnel
#  if one of them is 0 the other one will take place
#  otherwise the lower value will be used
def merge_settings(a, b):
    return min(a, b) if a and b else max(a, b)


# Parse an address and split hostname and port
#   If host or port is None the values are required
def parse_address(address, host=None, port=None):
    FORMAT_ERROR = "Invalid address parsed. Only host and port are supported."

    # Only the address without scheme and path
    if "/" in address:
        raise argparse.ArgumentTypeError(FORMAT_ERROR)

    # Try parsing with fixed scheme
    try:
        parsed = urlsplit(f"http://{address}")
        h, p = parsed.hostname, parsed.port
    except Exception:
        raise argparse.ArgumentTypeError(FORMAT_ERROR)

    # If host or port are None these must be parsed
    if not h and host is None:
        raise argparse.ArgumentTypeError("Host required.")
    if not p and port is None:
        raise argparse.ArgumentTypeError("Port required.")

    return h or host, p or port


# Check if a file exists and return the absolute path otherwise raise an error
def valid_file(path):
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError("Not a file.")

    return path


# Check if the argument is a valid port range with IP family
def valid_ports(ports):
    m = re.match(r"^(\d+):(\d+)?$", ports, re.IGNORECASE)
    if m:
        a, b = map(int, m.groups())
        if 0 < a < b < 65536:
            return a, b
        raise argparse.ArgumentTypeError("Port must be in range (1, 65536)")
    raise argparse.ArgumentTypeError("Invalid port scheme.")
