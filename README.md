[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/socket-proxy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# socket-proxy

This tool allows to forward TCP or HTTP ports to a server and make them available through the server.
TCP ports will be mapped to ports of the server. HTTP forwarding is done with a simple reverse
proxy using sub-domains. It consists of a client and server part. The server is listening for
incoming connections from clients and creates additional listeners upon connection. These can be
used to directly contact the TCP port set up as destination in the connecting client.

### Security

With this tool you can publish local service which might cause security issues for non-hardened
ports. You should consider further security measurements to harden critical systems if used. The
HTTP implementation is very basic and can't handle HTTPS. It's recommended to use a reverse proxy
like nginx with SSL and a wildcard certificate if HTTPS is required.

### Features

- TLS encryption of the tunnel
- Support for client certificates if CA is specified on the server
- Support for IPv4 and IPv6
- Proxy generic TCP ports or more specific HTTP servers
- Limitation of number of tunnels, clients per tunnel, and connections per IP
- Limit the access to specific IP's
- Configuration on server and client side and negotiation of the used settings

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
