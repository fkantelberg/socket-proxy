[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/socket-proxy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

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
- Support for client certificates if CA is specified on the server
- Support for IPv4 and IPv6
- Limitation of number of tunnels, clients per tunnel, and connections per IP

### Usage

1. Generate CA and certificates to be used on the server and client (e.g. using certs.sh of the package, easy-rsa, or openssl directly)

2. Start a tunnel server using a certificate and matching private key
```
$ socket_proxy server --cert certificate.pem --key certificate.key
```

3. Start a tunnel client and connect to a server. Tunnelled connections can access server reachable under TARGET:PORT
```
$ socket_proxy client --ca ca.pem -c SERVER -d TARGET:PORT
```

4. Connect clients to the opened ports on the server
