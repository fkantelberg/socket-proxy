#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from configparser import ConfigParser
from typing import Tuple

from . import base, utils
from .proxy import ProxyServer
from .tunnel_client import TunnelClient
from .tunnel_gui import GUIClient

_logger = logging.getLogger(__name__)


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)

        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return f"{'/'.join(action.option_strings)} {args_string}"


def basic_group(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Security")
    group.add_argument(
        "--config",
        default=None,
        type=argparse.FileType(),
        help="Load everything from a configuration file",
    )


def security_group(parser: argparse.ArgumentParser, server: bool) -> None:
    group = parser.add_argument_group("Security")

    text_ca = ["CA certificate to use."]
    text_cert = ["Certificate to use for establishing the connection."]
    text_key = ["Private key for the certificate."]

    if server:
        text_ca.append("Will enforce client certificates.")
    else:
        a = "Required if the target server enforces the client certificates."
        text_cert.append(a)
        text_key.append(a)

    group.add_argument(
        "--ca",
        default=None,
        metavar="FILE",
        type=utils.valid_file,
        help=" ".join(text_ca),
    )

    group.add_argument(
        "--cert",
        default=None,
        metavar="FILE",
        type=utils.valid_file,
        help=" ".join(text_cert),
    )
    group.add_argument(
        "--key",
        default=None,
        metavar="FILE",
        type=utils.valid_file,
        help=" ".join(text_key),
    )
    group.add_argument(
        "--cipher",
        default=None,
        help="Ciphers to use for the TLS connection.",
    )

    if not server:
        group.add_argument(
            "--no-verify-hostname",
            action="store_true",
            default=False,
            help="Disable the hostname verification. Only useful for clients.",
        )


def connection_group(parser: argparse.ArgumentParser, server: bool) -> None:
    group = parser.add_argument_group("Connection")
    if server:
        group.add_argument(
            "-l",
            "--listen",
            default=("", base.DEFAULT_PORT),
            dest="listen",
            metavar="[host[,host]*][:port]",
            type=lambda x: utils.parse_address(
                x,
                host="",
                port=base.DEFAULT_PORT,
                multiple=True,
            ),
            help=f"The address to listen on. If host is not given the server will "
            f"listen for connections from all IPs. If you want to listen on multiple "
            f"interfaces you can separate them by comma. If the port is not given "
            f"the server will listen on port {base.DEFAULT_PORT}.",
        )
        group.add_argument(
            "--http-domain",
            default=None,
            type=str,
            help="Specify the domain under which the sub-domains for the HTTP "
            "proxies will be created. If not specified the server won't be able to "
            "handle HTTP proxies.",
        )
        group.add_argument(
            "--http-listen",
            default=("", base.DEFAULT_HTTP_PORT),
            type=lambda x: utils.parse_address(
                x,
                host="",
                port=base.DEFAULT_HTTP_PORT,
                multiple=True,
            ),
            metavar="[host[,host]*][:port]",
            help=f"The address to listen on for HTTP proxies. If host is not given "
            f"the server will listen for connections from all IPs. If you want to "
            f"listen on multiple interfaces you can separate them by comma. If the "
            f"port is not given the server will listen on port "
            f"{base.DEFAULT_HTTP_PORT}.",
        )

        for protocol in base.ProtocolType:
            group.add_argument(
                f"--no-{protocol.name.lower()}",
                default=False,
                action="store_true",
                help=f"Disable the ability to forward {protocol.name} ports",
            )
    else:
        group.add_argument(
            "-c",
            "--connect",
            default=None,
            dest="connect",
            metavar="host[:port]",
            type=lambda x: utils.parse_address(x, port=base.DEFAULT_PORT),
            help=f"The address to connect with host[:port]. Required for clients. "
            f"(default: {base.DEFAULT_PORT})",
        )
        group.add_argument(
            "-d",
            "--dst",
            default=None,
            dest="dst",
            metavar="[host]:port",
            type=lambda x: utils.parse_address(x, host="localhost"),
            help="Target host and port for the connection. If the host is not "
            "given localhost will be used.",
        )
        group.add_argument(
            "--protocol",
            default=base.ProtocolType.TCP,
            type=base.ProtocolType.from_str,
            help="Select the protocol to be used. (default: tcp)",
        )


def logging_group(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Logging")
    group.add_argument(
        "--log-file",
        default=None,
        help="File to use for logging. If not set logs will be put to stdout.",
    )
    group.add_argument(
        "--log-level",
        choices=sorted(base.LOG_LEVELS),
        default=base.DEFAULT_LOG_LEVEL,
        help="Set the log level to use. (default: %(default)s)",
    )


def option_group(parser: argparse.ArgumentParser, server: bool) -> None:
    group = parser.add_argument_group(
        "Additional options",
        "If the tunnel server and client set the options the minimal value will be "
        "used.",
    )
    group.add_argument(
        "--ban-time",
        type=int,
        default=60,
        help="Seconds until the number of connects by an IP resets. "
        "(default: %(default)s)",
    )
    group.add_argument(
        "--max-clients",
        type=int,
        default=0,
        help="Maximum number of clients able to use the tunnel. This option "
        "can be set on the server and client. For the server it's the "
        "maximum number of clients per tunnel. (default: %(default)s)",
    )
    group.add_argument(
        "--max-connects",
        type=int,
        default=0,
        help="Maximum number of connects an IP is allowed to do within a "
        "certain time span. Disabled if 0. If set on both sites of the tunnel "
        " the lower number is used. (default: %(default)s)",
    )
    group.add_argument(
        "--idle-timeout",
        type=int,
        default=0,
        help="Timeout until the tunnel closes without interaction. "
        "(default: %(default)s)",
    )
    group.add_argument(
        "--networks",
        type=utils.parse_networks,
        default=[],
        help="Define comma separated networks in CIDR to allow only specific "
        "clients to connect to the server. (default: any)",
    )
    if server:
        group.add_argument(
            "--max-tunnels",
            type=int,
            default=0,
            help="Maximum number of tunnels. Only useful in server mode. "
            "(default: %(default)s)",
        )
        group.add_argument(
            "--tunnel-host",
            default=None,
            help="The IP the tunnels listen on. Supports the usage of commas to "
            "listen on different IPs. Each IP gets a different port. If not specified "
            "the tunnels will listen on 2 ports for all IPv4 and IPv6 connections.",
        )
        group.add_argument(
            "--ports",
            type=utils.valid_ports,
            help="Range of ports to use for the sockets.",
        )
    else:
        group.add_argument(
            "--no-curses",
            default="TERM" not in os.environ,
            action="store_true",
            help="Disable curses GUI",
        )
        group.add_argument(
            "--ping",
            default=False,
            action="store_true",
            help="Enable a regular ping and disconnect if the answer takes too long",
        )
        group.add_argument(
            "--store-information",
            default=None,
            type=argparse.FileType("w+"),
            help="Store the current connection information to a json file. This "
            "is especially useful if used as a service.",
        )


def parse_args(args: Tuple[str] = None) -> None:
    parser = utils.ConfigArgumentParser(
        formatter_class=CustomHelpFormatter,
        prog="",
        description="",
    )
    logging_group(parser)

    sub = parser.add_subparsers(dest="mode")

    client = sub.add_parser(
        "client",
        formatter_class=CustomHelpFormatter,
        help="Enter client mode connect to a server building the tunnel.",
    )
    basic_group(client)
    security_group(client, False)
    connection_group(client, False)
    option_group(client, False)
    logging_group(client)

    server = sub.add_parser(
        "server",
        formatter_class=CustomHelpFormatter,
        help="Enter server mode and listen for incoming clients to build the tunnels.",
    )
    basic_group(server)
    security_group(server, True)
    connection_group(server, True)
    option_group(server, True)
    logging_group(server)

    parsed = parser.parse_args(args)
    if not getattr(parsed, "config", None) or not parsed.mode:
        return parsed

    cp = ConfigParser()
    cp.read_file(parsed.config)
    if not cp.has_section(parsed.mode):
        return parsed
    return parser.parse_with_config(args, dict(cp.items(parsed.mode)))


def run_client(no_curses: bool) -> None:
    for arg in ["ca", "connect", "dst"]:
        if not getattr(base.config, arg, False):
            _logger.critical("Missing --%s argument", arg)
            sys.exit(1)

    cls = TunnelClient if no_curses else GUIClient

    cli = cls(
        *base.config.connect,
        *base.config.dst,
        ca=base.config.ca,
        cert=base.config.cert,
        key=base.config.key,
        protocol=base.config.protocol,
        verify_hostname=not base.config.no_verify_hostname,
        networks=base.config.networks,
        ping_enabled=base.config.ping,
    )
    cli.start()


def run_server() -> None:
    for arg in ["cert", "key"]:
        if not getattr(base.config, arg, False):
            _logger.critical("Missing --%s argument", arg)
            sys.exit(1)

    server = ProxyServer(
        *base.config.listen,
        ca=base.config.ca,
        cert=base.config.cert,
        key=base.config.key,
        http_domain=base.config.http_domain,
        tunnel_host=base.config.tunnel_host,
        ports=base.config.ports,
        networks=base.config.networks,
    )
    server.start()


def main(args: Tuple[str] = None) -> None:
    base.config = parse_args(args)

    utils.configure_logging(base.config.log_file, base.config.log_level)

    try:
        if base.config.mode == "server":
            run_server()
        elif base.config.mode == "client":
            run_client(base.config.no_curses)
    except KeyboardInterrupt:
        _logger.info("Shutting down")


if __name__ == "__main__":
    main()
