from __future__ import annotations

from functools import wraps
from typing import Awaitable, Callable, TypeVar

from watchtower.client import GuardResult, SentinelClient

F = TypeVar("F", bound=Callable[..., Awaitable[str]])


def sentinel_guard(
    agent_id: str,
    *,
    base_url: str = "http://localhost:8000",
    client: SentinelClient | None = None,
) -> Callable[[F], F]:
    """Decorator — wrap any async agent handler with WatchTower protection.

    Example::

        sentinel = SentinelClient()

        @sentinel_guard("travel", client=sentinel)
        async def handle(user_message: str) -> str:
            result = graph.invoke({"messages": [("user", user_message)]})
            return result["messages"][-1].content
    """

    _client = client or SentinelClient(base_url)

    def decorator(fn: F) -> F:
        @wraps(fn)
        async def wrapper(message: str, *args, **kwargs) -> str:
            result = await _client.protect(
                agent_id=agent_id,
                message=message,
                run=lambda: fn(message, *args, **kwargs),
            )
            if result.blocked:
                return result.response or f"Blocked by SentinelAI: {result.threat}"
            return result.response or ""

        return wrapper  # type: ignore[return-value]

    return decorator
