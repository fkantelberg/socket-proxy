[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/socket-proxy)

# socket-proxy

This tool allows to forward TCP ports to a server and make them accessible through ports
of the server. It consists of a client and server part. The server is listening for
incoming connections from clients and creates additional listeners upon connection.
These can be used to directly contact the TCP port set up as destination in the
connecting client.

### Security

With this tool you are publishing local ports which might cause security issues for
non-hardened ports.

### Features

- TLS encryption of the tunnel
- Client certificates
- Support for IPv4 and IPv6 (different ports)
- Limitation of number of tunnels, clients per tunnel and connections per IP
