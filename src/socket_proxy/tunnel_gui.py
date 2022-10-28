import curses
import logging
import queue
from logging.handlers import QueueHandler
from typing import List

from .base import LOG_FORMAT, InternetType
from .tunnel_client import TunnelClient
from .utils import format_transfer

_logger = logging.getLogger(__name__)


class GUIClient(TunnelClient):
    """ncurses GUI for tunnel clients"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.options = 10
        self.logs = []
        self.width = self.height = 0
        self.scr = None
        self.configure_logging()

    def configure_logging(self) -> None:
        """Reconfigure the logging to catch the messages for the GUI"""
        self.log_queue = queue.Queue()
        self.log_handler = QueueHandler(self.log_queue)
        self.log_handler.setFormatter(logging.Formatter(LOG_FORMAT, style="{"))
        logging.getLogger().handlers = [self.log_handler]

    def get_dimension(self) -> None:
        """Get the dimensions of the current window"""
        self.height, self.width = self.scr.getmaxyx()

    def _draw(self) -> None:
        """Draw all GUI elements"""
        self.scr.clear()
        self._draw_config()
        self._draw_info()
        self._draw_log()

    def _draw_info(self) -> None:
        """Draw a box with main information about the current status"""
        win = self.scr.subwin(self.options, self.width // 2, 0, 0)
        win.box()
        win.border(0)
        bytes_in = self.bytes_in + sum(cl.bytes_in for cl in self.clients.values())
        bytes_out = self.bytes_out + sum(cl.bytes_out for cl in self.clients.values())
        win.addstr(0, 2, "Info")

        if self.last_ping and self.last_pong:
            ping_time = f"{1000 * (self.last_pong - self.last_ping):.0f} ms"
        else:
            ping_time = "-"

        addr = [(InternetType.from_ip(ip), ip, port) for ip, port in self.addr]
        lines = [f"Listen on {self.fmt_port(*a)}" for a in sorted(addr[:2])]
        lines.extend(
            [
                "-" * (win.getmaxyx()[1] - 4),
                f"Clients: {len(self.clients)}",
                f"Domain: {self.domain or 'off'}",
                f"Ping: {ping_time}",
                f"Transfer In: {format_transfer(bytes_out)}",
                f"Transfer Out: {format_transfer(bytes_in)}",
            ]
        )

        self._draw_lines(win, lines)
        win.refresh()
        return win

    def _draw_config(self) -> None:
        """Draw a box with the current tunnel configuration"""
        mx, my = self.width // 2, self.options
        win = self.scr.subwin(my, self.width - mx, 0, mx)
        win.box()
        win.border(0)
        win.addstr(0, 2, "Configuration")

        networks = self.networks if self.networks else ["0.0.0.0/0", "::/0"]
        self._draw_lines(
            win,
            [
                f"Allowed Networks: {', '.join(map(str, networks))}",
                f"Ban time: {self.bantime or 'off'}",
                f"Connections per IP: {self.max_connects or '-'}",
                f"Idle Timeout: {self.idle_timeout or 'off'}",
                f"Max Clients: {self.max_clients or '-'}",
                f"Ping: {'on' if self.ping_enabled else 'off'}",
                f"Protocol: {self.protocol.name}",
            ],
        )
        win.refresh()
        return win

    def _draw_log(self) -> None:
        """Draw a box with the latest logs"""
        h = self.height - self.options - 4
        w = self.width - 4

        win = self.scr.subwin(h + 4, w + 4, self.options, 0)
        win.box()
        win.border(0)
        win.addstr(0, 2, "Log")

        while not self.log_queue.empty():
            self.logs.append(self.log_queue.get().msg)

        self.logs = self.logs[-h - 2 :]

        self._draw_lines(win, self.logs)

        win.refresh()
        return win

    def _draw_lines(self, win, lines: List[str]) -> None:
        """Draw multiple lines in a window with some border"""
        h, w = [k - 2 for k in win.getmaxyx()]
        for y, line in enumerate(lines[:h]):
            win.addstr(y + 1, 2, line[:w])

    async def _handle(self) -> bool:
        """Handle the drawing after each package"""
        self.get_dimension()
        self._draw()
        return await super()._handle()

    def _gui(self, scr) -> None:
        """Configure the main screen"""
        self.scr = scr
        curses.noecho()
        curses.curs_set(0)

        super().start()

    def start(self) -> None:
        curses.wrapper(self._gui)
