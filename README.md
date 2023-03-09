[![main](https://github.com/fkantelberg/socket-proxy/actions/workflows/main.yaml/badge.svg)](https://github.com/fkantelberg/socket-proxy/actions/workflows/main.yaml)
![Coverage](https://github.com/fkantelberg/socket-proxy/blob/master/coverage.svg)
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
HTTP implementation is very basic. It's recommended to use a reverse proxy
like nginx with SSL and a wildcard certificate if HTTPS is required.

### Features

- TLS encryption of the tunnel
- Support for client certificates if CA is specified on the server
- Support for token authentication. These tokens are rotating automatically
- Support for IPv4 and IPv6
- Proxy generic TCP ports or more specific HTTP servers
- Limitation of number of tunnels, clients per tunnel, and connections per IP
- Limit the access to specific IP's
- Configuration on server and client side and negotiation of the used settings
- Web API with support of bearer authentication

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

### Web API Client

`GET /` returns the state of the server as JSON dictionary. Use the path to get only specific information.
E.g. `/clients` only returns the sub-dictionary `clients` and `/clients/edcb13dc0c7c6c64` returns only
information about the client `edcb13dc0c7c6c64`.

`DELETE /<client>` disconnects the client `<client>`.

The client side API doesn't support SSL!

### Web API Server

`GET /` returns the state of the server as JSON dictionary. Use the path to get only specific information.
E.g. `/tunnels` only returns the sub-dictionary `tunnels` and `/tunnels/edcb13dc0c7c6c64` returns only
information about the tunnel `edcb13dc0c7c6c64`.

`GET /api/token` returns a new authentication token as JSON string.

`DELETE /<tunnel>/<client>` disconnects the client `<client>` of the tunnel `<tunnel>`.

`DELETE /<tunnel>` disconnects the tunnel `<tunnel>`.
