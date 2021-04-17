from argparse import FileType, Namespace
from configparser import ConfigParser
from typing import Any, Set

from . import base, utils


def to_bool(x: str) -> bool:
    return x.lower() in ["1", "on", "true", "t"]


OptionDefault = {
    "ban-time": 60,
    "http-domain": None,
    "http-listen": ("", base.DEFAULT_HTTP_PORT),
    "idle-timeout": 0,
    "listen": ("", base.DEFAULT_PORT),
    "log-file": None,
    "log-level": base.DEFAULT_LOG_LEVEL,
    "max-clients": 0,
    "max-connects": 0,
    "max-tunnels": 0,
    "networks": [],
    "no-verify-hostname": False,
    "ports": None,
    "protocol": base.ProtocolType.TCP,
    "protocols": [base.ProtocolType.TCP],
    "store-information": None,
    "tunnel-host": None,
}


OptionType = {
    "ban-time": int,
    "ca": utils.valid_file,
    "cert": utils.valid_file,
    "connect": lambda x: utils.parse_address(x, port=base.DEFAULT_PORT),
    "dst": lambda x: utils.parse_address(x, host="localhost"),
    "http-domain": str,
    "http-listen": lambda x: utils.parse_address(
        x, host="", port=base.DEFAULT_HTTP_PORT, multiple=True,
    ),
    "idle-timeout": int,
    "key": utils.valid_file,
    "listen": lambda x: utils.parse_address(
        x, host="", port=base.DEFAULT_PORT, multiple=True,
    ),
    "log-file": str,
    "log-level": str,
    "max-clients": int,
    "max-connects": int,
    "max-tunnels": int,
    "networks": utils.parse_networks,
    "no-verify-hostname": to_bool,
    "ports": utils.valid_ports,
    "protocol": base.ProtocolType.from_str,
    "store-information": FileType("w+"),
    "tunnel-host": str,
    **{f"no-{protocol.name.lower()}": to_bool for protocol in base.ProtocolType},
}


class Configuration:
    """ Helper class for the configuration management """

    def __init__(self):
        self.config = OptionDefault.copy()

    def __contains__(self, key: Any) -> bool:
        return key in self.config

    def __getitem__(self, key: Any) -> Any:
        return self.config[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self.config[key] = value

    @property
    def protocols(self) -> Set[base.ProtocolType]:
        result = set()
        for protocol in base.ProtocolType:
            if not self.get(f"no-{protocol.name.lower()}"):
                result.add(protocol)

        if not self.get("http-domain"):
            result.discard(base.ProtocolType.HTTP)
        return result

    def get(self, key: Any, default: Any = None) -> Any:
        return self.config.get(key, default)

    def load(self, section: str, filename: str) -> bool:
        cfg = ConfigParser()
        cfg.read(filename)

        if section not in cfg:
            return False

        for opt, value in cfg[section].items():
            self[opt] = OptionType.get(opt, str)(value)

        return True

    def load_arguments(self, args: Namespace) -> None:
        for opt in OptionType:
            arg = opt.replace("-", "_")
            val = getattr(args, arg, None)
            if self.get(opt) is None or val is not None:
                self[opt] = val


config = Configuration()
