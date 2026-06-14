"""Shared travel agent builder — used by Jupyter demo and backend."""

from __future__ import annotations

import os


def search_flights(origin: str, destination: str) -> str:
    return (
        f"Found 3 flights {origin} → {destination}. "
        f"Best: ANA NH848 departing 06:45, ¥42,500."
    )


def search_hotels(city: str, nights: int = 1) -> str:
    return f"Found 12 hotels in {city} from ¥8,000/night ({nights} night(s))."


TOOLS = [search_flights, search_hotels]


def require_openai() -> None:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "Set OPENAI_API_KEY for the real demo. "
            "export OPENAI_API_KEY=sk-... before starting Jupyter."
        )


def build_travel_graph():
    """Build a real LangGraph ReAct agent with OpenAI."""
    require_openai()
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), temperature=0)
    return create_react_agent(llm, TOOLS)


def invoke_graph(graph, message: str) -> dict:
    result = graph.invoke({"messages": [{"role": "user", "content": message}]})
    messages = result.get("messages", [])
    last = messages[-1] if messages else None
    content = getattr(last, "content", str(last)) if last else ""
    tool_calls = []
    for m in messages:
        if hasattr(m, "tool_calls") and m.tool_calls:
            for tc in m.tool_calls:
                name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "tool")
                args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                tool_calls.append({"name": name, "detail": f"{name}({args})"})
    return {"messages": messages, "response": content, "tool_calls": tool_calls}
