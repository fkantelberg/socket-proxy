import enum
import logging
from asyncio import Queue
from typing import Any, Optional

from . import base

try:
    from aiohttp import ClientSession
    from aiohttp.client_exceptions import ClientError
except ImportError:
    ClientError = ClientSession = None  # type: ignore

_logger = logging.getLogger(__name__)


class EventType(enum.IntEnum):
    Client = 0x01
    Server = 0x02


class EventSystem:
    """Event system where events are send via hooks"""

    def __init__(
        self,
        event_type: EventType,
        *,
        url: Optional[str] = None,
        token: Optional[str] = None,
    ):
        self.event_type: EventType = event_type
        self.enabled: bool = bool(ClientSession is not None and url)
        self.event_url: str = url or "" if self.enabled else ""
        self.queue: Queue = Queue()
        self.event_token: Optional[str] = (
            f"Bearer {token}" if token and self.enabled else None
        )

    async def send(self, *, msg: str, **data: Any) -> bool:
        """Enqueue an event"""
        if not self.enabled:
            return False

        await self.queue.put({**data, "message": msg})
        return True

    def send_nowait(self, *, msg: str, **data: Any) -> bool:
        """Enqueue an event"""
        if not self.enabled:
            return False

        self.queue.put_nowait({**data, "message": msg})
        return True

    async def flush(self) -> None:
        """Send the events to the hooks"""
        if self.queue.empty() or not self.enabled:
            return

        headers = {"Authorization": self.event_token} if self.event_token else {}
        async with ClientSession(headers=headers) as session:
            while not self.queue.empty():
                msg = await self.queue.get()
                try:
                    response = await session.post(
                        self.event_url,
                        json=msg,
                        timeout=base.EVENT_TIMEOUT,
                    )

                    if response.status not in (200, 202):
                        await self.queue.put(msg)
                        break
                except ClientError:
                    await self.queue.put(msg)
                    break
