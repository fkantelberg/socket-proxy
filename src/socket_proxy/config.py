from configparser import ConfigParser

from . import base, utils


def to_bool(x):
    return x.lower() in ["1", "on", "true", "t"]


OptionDefault = {
    "ban-time": 60,
    "http-domain": None,
    "http-listen": ("", base.DEFAULT_HTTP_PORT),
    "idle-timeout": 0,
    "listen": ("", base.DEFAULT_PORT),
    "log-file": base.DEFAULT_LOG_LEVEL,
    "log-level": None,
    "max-clients": 0,
    "max-connects": 0,
    "max-tunnels": 0,
    "networks": [],
    "no-verify-hostname": False,
    "ports": None,
    "protocol": base.ProtocolType.TCP,
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
    "tunnel-host": str,
}


class Configuration:
    """ Helper class for the configuration management """

    def __init__(self):
        self.config = OptionDefault.copy()

    def __contains__(self, key):
        return key in self.config

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, value):
        self.config[key] = value

    def get(self, key, default=None):
        return self.config.get(key, default)

    def load(self, section, filename):
        cfg = ConfigParser()
        cfg.read(filename)

        if section not in cfg:
            return False

        for opt, value in cfg[section].items():
            self[opt] = OptionType.get(opt, str)(value)

        return True

    def load_arguments(self, args):
        for opt in OptionType:
            arg = opt.replace("-", "_")
            val = getattr(args, arg, None)
            if self.get(opt) is None or val is not None:
                self[opt] = val


config = Configuration()
