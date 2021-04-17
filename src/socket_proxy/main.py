#!/usr/bin/env python3
import argparse
import logging
import os
import sys
from typing import Tuple

from .base import (
    DEFAULT_HTTP_PORT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_PORT,
    LOG_LEVELS,
    ProtocolType,
)
from .config import OptionType, config
from .proxy import ProxyServer
from .tunnel_client import TunnelClient
from .tunnel_gui import GUIClient
from .utils import configure_logging

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
        "--config", help="Load everything from a configuration file",
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
        "--ca", metavar="FILE", type=OptionType["ca"], help=" ".join(text_ca),
    )

    group.add_argument(
        "--cert", metavar="FILE", type=OptionType["cert"], help=" ".join(text_cert),
    )
    group.add_argument(
        "--key", metavar="FILE", type=OptionType["key"], help=" ".join(text_key),
    )
    group.add_argument(
        "--cipher", help="Ciphers to use for the TLS connection.",
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
            dest="listen",
            metavar="[host[,host]*][:port]",
            type=OptionType["listen"],
            help=f"The address to listen on. If host is not given the server will "
            f"listen for connections from all IPs. If you want to listen on multiple "
            f"interfaces you can separate them by comma. If the port is not given "
            f"the server will listen on port {DEFAULT_PORT}.",
        )
        group.add_argument(
            "--http-domain",
            type=OptionType["http-domain"],
            help="Specify the domain under which the sub-domains for the HTTP "
            "proxies will be created. If not specified the server won't be able to "
            "handle HTTP proxies.",
        )
        group.add_argument(
            "--http-listen",
            type=OptionType["http-listen"],
            metavar="[host[,host]*][:port]",
            help=f"The address to listen on for HTTP proxies. If host is not given "
            f"the server will listen for connections from all IPs. If you want to "
            f"listen on multiple interfaces you can separate them by comma. If the "
            f"port is not given the server will listen on port "
            f"{DEFAULT_HTTP_PORT}.",
        )

        for protocol in ProtocolType:
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
            dest="connect",
            metavar="host[:port]",
            type=OptionType["connect"],
            help=f"The address to connect with host[:port]. Required for clients. "
            f"(default: {DEFAULT_PORT})",
        )
        group.add_argument(
            "-d",
            "--dst",
            dest="dst",
            metavar="[host]:port",
            type=OptionType["dst"],
            help="Target host and port for the connection. If the host is not "
            "given localhost will be used.",
        )
        group.add_argument(
            "--protocol",
            type=OptionType["protocol"],
            help="Select the protocol to be used. (default: tcp)",
        )


def logging_group(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Logging")
    group.add_argument(
        "--log-file",
        help="File to use for logging. If not set logs will be put to stdout.",
    )
    group.add_argument(
        "--log-level",
        choices=sorted(LOG_LEVELS),
        default=DEFAULT_LOG_LEVEL,
        help="Set the log level to use. (default: %(default)s)",
    )


def option_group(parser: argparse.ArgumentParser, server: bool) -> None:
    group = parser.add_argument_group(
        "Additional options",
        "If the tunnel server and client set the options the minimal value will be used.",
    )
    group.add_argument(
        "--ban-time",
        type=OptionType["ban-time"],
        default=60,
        help="Seconds until the number of connects by an IP resets. "
        "(default: %(default)s)",
    )
    group.add_argument(
        "--max-clients",
        type=OptionType["max-clients"],
        default=0,
        help="Maximum number of clients able to use the tunnel. This option "
        "can be set on the server and client. For the server it's the "
        "maximum number of clients per tunnel. (default: %(default)s)",
    )
    group.add_argument(
        "--max-connects",
        type=OptionType["max-connects"],
        default=0,
        help="Maximum number of connects an IP is allowed to do within a "
        "certain time span. Disabled if 0. If set on both sites of the tunnel "
        " the lower number is used. (default: %(default)s)",
    )
    group.add_argument(
        "--idle-timeout",
        type=OptionType["idle-timeout"],
        default=0,
        help="Timeout until the tunnel closes without interaction. "
        "(default: %(default)s)",
    )
    group.add_argument(
        "--networks",
        type=OptionType["networks"],
        default=[],
        help="Define comma separated networks in CIDR to allow only specific "
        "clients to connect to the server. (default: any)",
    )
    if server:
        group.add_argument(
            "--max-tunnels",
            type=OptionType["max-tunnels"],
            default=0,
            help="Maximum number of tunnels. Only useful in server mode. "
            "(default: %(default)s)",
        )
        group.add_argument(
            "--tunnel-host",
            help="The IP the tunnels listen on. Supports the usage of commas to "
            "listen on different IPs. Each IP gets a different port. If not specified "
            "the tunnels will listen on 2 ports for all IPv4 and IPv6 connections.",
        )
        group.add_argument(
            "--ports",
            type=OptionType["ports"],
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
            "--store-information",
            type=OptionType["store-information"],
            help="Store the current connection information to a json file. This "
            "is especially useful if used as a service.",
        )


def parse_args(args: Tuple[str] = None) -> None:
    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter, prog="", description="",
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

    return parser.parse_args(args)


def run_client(no_curses: bool) -> None:
    for arg in ["ca", "connect", "dst"]:
        if not config.get(arg, False):
            _logger.critical("Missing --%s argument", arg)
            sys.exit(1)

    cls = TunnelClient if no_curses else GUIClient

    cli = cls(
        *config["connect"],
        *config["dst"],
        ca=config["ca"],
        cert=config["cert"],
        key=config["key"],
        protocol=config["protocol"],
        verify_hostname=not config["no-verify-hostname"],
        networks=config["networks"],
    )
    cli.start()


def run_server() -> None:
    for arg in ["cert", "key"]:
        if not config.get(arg, False):
            _logger.critical("Missing --%s argument", arg)
            sys.exit(1)

    server = ProxyServer(
        *config["listen"],
        ca=config["ca"],
        cert=config["cert"],
        key=config["key"],
        http_domain=config["http-domain"],
        tunnel_host=config["tunnel-host"],
        ports=config["ports"],
        networks=config["networks"],
    )
    server.start()


def main(args: Tuple[str] = None) -> None:
    args = parse_args(args)

    if args.config:
        config.load(args.mode, args.config)

    config.load_arguments(args)

    configure_logging(config.get("log-file"), config.get("log-level"))

    try:
        if args.mode == "server":
            run_server()
        elif args.mode == "client":
            run_client(config.get("no-curses"))
    except KeyboardInterrupt:
        _logger.info("Shutting down")


if __name__ == "__main__":
    main()
