"""Bridge between registered LangGraph agents and WatchTower state."""

from __future__ import annotations

from .agents.travel_graph import invoke_travel_agent


def run_registered_agent(agent_id: str, message: str) -> dict:
    if agent_id in ("travel", "travel-agent"):
        return invoke_travel_agent(message)
    return {
        "response": f"No registered agent for '{agent_id}'. Using simulated response.",
        "tool_calls": [],
        "engine": "none",
    }
