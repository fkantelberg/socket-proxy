#!/usr/bin/env python3
import argparse
import logging
import sys

from base import DEFAULT_LOG_LEVEL, DEFAULT_PORT, LOG_LEVELS
from proxy import ProxyServer
from tunnel import TunnelClient
from utils import configure_logging, parse_address, valid_file

_logger = logging.getLogger(__name__)


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)

        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return f"{'/'.join(action.option_strings)} {args_string}"


def security_group(parser, server: bool):
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
        "--ca", metavar="FILE", type=valid_file, help=" ".join(text_ca),
    )

    group.add_argument(
        "--cert",
        metavar="FILE",
        type=valid_file,
        required=server,
        help=" ".join(text_cert),
    )
    group.add_argument(
        "--key",
        metavar="FILE",
        type=valid_file,
        required=server,
        help=" ".join(text_key),
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


def connection_group(parser, server: bool):
    group = parser.add_argument_group("Connection")
    if server:
        group.add_argument(
            "-l",
            "--listen",
            dest="listen",
            metavar="[host][:port]",
            default=("", DEFAULT_PORT),
            type=lambda x: parse_address(x, host="", port=DEFAULT_PORT),
            help=f"The address to listen on. If host is not given the server will "
            f"listen for connections from all IPs. If the port is not given "
            f"the server will listen on port {DEFAULT_PORT}.",
        )
    else:
        group.add_argument(
            "-c",
            "--connect",
            dest="connect",
            metavar="host[:port]",
            type=lambda x: parse_address(x, port=DEFAULT_PORT),
            help=f"The address to connect with host[:port]. Required for clients. "
            f"The default port is {DEFAULT_PORT}.",
        )
        group.add_argument(
            "-d",
            "--dst",
            dest="dst",
            metavar="[host]:port",
            type=lambda x: parse_address(x, host="localhost"),
            help="Target host and port for the connection. If the host is not "
            "given localhost will be used.",
        )


def option_group(parser, server: bool):
    group = parser.add_argument_group("Options")
    group.add_argument(
        "--log-file",
        help="File to use for logging. If not set logs will be put to stdout.",
    )
    group.add_argument(
        "--log-level",
        choices=sorted(LOG_LEVELS),
        default="DEBUG",
        help=f"Set the log level to use. Default is {DEFAULT_LOG_LEVEL}.",
    )
    group.add_argument(
        "--ban-time",
        type=int,
        default=60,
        help="Seconds until the number of connects by an IP resets.",
    )
    group.add_argument(
        "--max-clients",
        type=int,
        default=0,
        help="Maximum number of clients able to use the tunnel. This option "
        "can be set on the server and client. For the server it's the "
        "maximum number of clients per tunnel.",
    )
    group.add_argument(
        "--max-connects",
        type=int,
        default=0,
        help="Maximum number of connects an IP is allowed to do within a "
        "certain time span. Disabled if 0. If set on both sites of the tunnel "
        " the lower number is used.",
    )
    if server:
        group.add_argument(
            "--max-tunnels",
            type=int,
            default=0,
            help="Maximum number of tunnels. Only useful in server mode.",
        )


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter, prog="", description=""
    )

    sub = parser.add_subparsers(dest="mode")

    client = sub.add_parser(
        "client",
        formatter_class=CustomHelpFormatter,
        help="Enter client mode connect to a server building the tunnel.",
    )
    security_group(client, False)
    connection_group(client, False)
    option_group(client, False)

    server = sub.add_parser(
        "server",
        formatter_class=CustomHelpFormatter,
        help="Enter server mode and listen for incoming clients to build the tunnels.",
    )
    security_group(server, True)
    connection_group(server, True)
    option_group(server, True)

    return parser.parse_args()


def run_client(args):
    for arg in ["ca", "connect", "dst"]:
        if not getattr(args, arg):
            _logger.critical("Missing -%s argument", arg)
            sys.exit(1)

    cli = TunnelClient(
        *args.connect,
        *args.dst,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
        bantime=args.ban_time,
        max_clients=args.max_clients,
        max_connects=args.max_connects,
        verify_hostname=not args.no_verify_hostname,
    )
    cli.run()


def run_server(args):
    for arg in ["cert", "key"]:
        if not getattr(args, arg):
            _logger.critical("Missing -%s argument", arg)
            sys.exit(1)

    server = ProxyServer(
        *args.listen,
        ca=args.ca,
        cert=args.cert,
        key=args.key,
        bantime=args.ban_time,
        max_clients=args.max_clients,
        max_connects=args.max_connects,
        max_tunnels=args.max_tunnels,
    )
    server.run()


def main():
    args = parse_args()

    configure_logging(args.log_file, args.log_level)

    try:
        if args.mode == "server":
            run_server(args)
        elif args.mode == "client":
            run_client(args)
    except KeyboardInterrupt:
        _logger.info("Shutting down")


if __name__ == "__main__":
    main()