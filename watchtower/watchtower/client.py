from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

import httpx

T = TypeVar("T")
RunFn = Callable[[], Awaitable[T] | T]


@dataclass
class GuardResult:
    blocked: bool
    response: str | None = None
    threat: str | None = None
    confidence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class SentinelClient:
    """Connect any agent to the SentinelAI / WatchTower dashboard."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def register_agent(self, agent_id: str, name: str, description: str = "") -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base_url}/api/agents/register",
                json={"agent_id": agent_id, "name": name, "description": description},
            )
            r.raise_for_status()
            return r.json()

    async def inspect(self, message: str, agent_id: str = "travel") -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base_url}/api/sentinel/inspect",
                json={"message": message, "agent_id": agent_id},
            )
            r.raise_for_status()
            return r.json()

    async def reset(self) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(f"{self.base_url}/api/demo/reset")
            r.raise_for_status()
            return r.json()

    async def protect(
        self,
        agent_id: str,
        message: str,
        run: RunFn[T] | None = None,
        *,
        agent_name: str | None = None,
        engine: str = "openai+langgraph",
    ) -> GuardResult:
        """Guard a prompt and run your agent. Dashboard updates live via WebSocket.

        Typical Jupyter usage::

            result = await sentinel.protect(
                "travel",
                user_message,
                run=lambda: graph.invoke({"messages": [("user", user_message)]}),
            )
        """
        if agent_name:
            await self.register_agent(agent_id, agent_name)

        if run is None:
            return await self._protect_server(agent_id, message)

        inspection = await self.inspect(message, agent_id)
        if inspection.get("blocked"):
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                await client.post(
                    f"{self.base_url}/api/agent/run",
                    json={"message": message, "agent_id": agent_id, "mode": "block_only"},
                )
            return GuardResult(
                blocked=True,
                threat=inspection.get("threat") or "Blocked",
                confidence=inspection.get("confidence", 0),
                metadata=inspection,
            )

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            start = await client.post(
                f"{self.base_url}/api/agent/start",
                json={"message": message, "agent_id": agent_id},
            )
            start.raise_for_status()

        outcome = run()
        if asyncio.iscoroutine(outcome):
            outcome = await outcome

        response_text = extract_text(outcome)
        tool_calls = extract_tool_calls(outcome)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            await client.post(
                f"{self.base_url}/api/agent/complete",
                json={
                    "message": message,
                    "agent_id": agent_id,
                    "response": response_text,
                    "tool_calls": tool_calls,
                    "engine": engine,
                },
            )

        return GuardResult(blocked=False, response=response_text, metadata={"raw": outcome})

    async def _protect_server(self, agent_id: str, message: str) -> GuardResult:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base_url}/api/agent/run",
                json={"message": message, "agent_id": agent_id, "mode": "langgraph"},
            )
            r.raise_for_status()
            return GuardResult(blocked=False, metadata=r.json())

    def protect_sync(self, agent_id: str, message: str, run: RunFn[T] | None = None, **kwargs) -> GuardResult:
        return asyncio.run(self.protect(agent_id, message, run, **kwargs))

    def reset_sync(self) -> dict:
        return asyncio.run(self.reset())


def extract_text(outcome: Any) -> str:
    if isinstance(outcome, str):
        return outcome
    if isinstance(outcome, dict):
        if "response" in outcome:
            return str(outcome["response"])
        messages = outcome.get("messages", [])
        if messages:
            last = messages[-1]
            if isinstance(last, dict):
                return str(last.get("content", last))
            return str(getattr(last, "content", last))
    return str(outcome)


def extract_tool_calls(outcome: Any) -> list[dict[str, str]]:
    if isinstance(outcome, dict):
        if "tool_calls" in outcome:
            return outcome["tool_calls"]
        messages = outcome.get("messages", [])
        for m in messages:
            if hasattr(m, "tool_calls") and m.tool_calls:
                return [
                    {"name": tc.get("name", "tool"), "detail": str(tc.get("args", tc))}
                    for tc in m.tool_calls
                ]
    return []
