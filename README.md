[![main](https://github.com/fkantelberg/socket-proxy/actions/workflows/main.yaml/badge.svg)](https://github.com/fkantelberg/socket-proxy/actions/workflows/main.yaml)
![Coverage](https://github.com/fkantelberg/socket-proxy/blob/master/coverage.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/socket-proxy)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# socket-proxy

This tool allows to forward TCP ports through a proxy server. The proxy server can expose
the listening port directly or bridge the port between two clients allowing the bridge client
to expose the listening port. Afterwards the applications can connect directly to the
exposed ports like they were connected to the listening port. For easier handling
HTTP ports can directly be addressed and the proxy server exposed those throw sub-domains
as a simple reverse proxy.

### Security

With this tool you can publish local service which might cause security issues for non-hardened
ports. You should consider further security measurements to harden critical systems if used. The
HTTP implementation is very basic. It's recommended to use a reverse proxy
like nginx with SSL and a wildcard certificate if HTTPS is required.

### Features

- TLS encryption of the tunnel
- Support for client certificates if CA is specified on the server
- Support for token authentication. These tokens are rotating automatically
- Bridge mode to allow to forward a port from one client to another bridge client
- Support for IPv4 and IPv6
- Proxy generic TCP ports or more specific HTTP servers
- Limitation of number of tunnels, clients per tunnel, and connections per IP
- Limit the access to specific IP's
- Configuration on server and client side and negotiation of the used settings
- Web API with support of bearer authentication. The API allows to look into the proxy server, client or bridge client
- Event system to send HTTP POST requests to a webhook with information about the event

### Usage

The below examples are assuming the minimal necessary certificates. You can generate CA and
certificates to be used on the server and client (e.g. using certs.sh of the package,
easy-rsa, or openssl directly).

#### Direct exposure on the proxy server

1. Start a proxy server using a certificate and matching private key
```
$ socket_proxy server --cert certificate.pem --key certificate.key
```

2. Start a tunnel client and connect to a server. Tunnelled connections can access server reachable under TARGET:PORT
```
$ socket_proxy client --ca ca.pem -c SERVER -d TARGET:PORT
```

3. Connect clients to the opened ports on the server (see the log or the API for the correct port)

#### Bridge mode and exposure on a bridge client

1. Start a proxy server using a certificate and matching private key
```
$ socket_proxy server --cert certificate.pem --key certificate.key
```

2. Start a tunnel client and connect to a server. Tunnelled connections can access server reachable under TARGET:PORT. Additional we specify that we want to bridge it using `--protocol`. See the log or API for the bridge token
```
$ socket_proxy client --ca ca.pem -c SERVER -d TARGET:PORT --protocol bridge
```

3. Connect an additional client to bridge the port and expose it locally
```
$ socket_proxy bridge --ca ca.pem -c SERVER --bridge BRIDGE_TOKEN
```

4. Connect clients to the opened ports on the bridge client (see the log or the API for the correct port)

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
