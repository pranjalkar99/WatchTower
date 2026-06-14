#!/usr/bin/env python3
"""Standalone demo: LangGraph travel agent with and without WatchTower.

Usage:
    pip install -e ../watchtower langgraph langchain-core
    python run.py                    # without WatchTower
    python run.py --with-watchtower  # 3-line integration
    OPENAI_API_KEY=sk-... python run.py --with-watchtower  # real OpenAI
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

# Allow importing the backend travel graph from the monorepo
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(ROOT, "backend"))

from app.agents.travel_graph import invoke_travel_agent  # noqa: E402


def run_bare(message: str) -> None:
    print("\n[bare agent — no security layer]\n")
    result = invoke_travel_agent(message)
    print(f"Engine: {result['engine']}")
    print(f"Response: {result['response']}")
    if result["tool_calls"]:
        print(f"Tools: {result['tool_calls']}")


async def run_protected(message: str, base_url: str) -> None:
    from watchtower import SentinelClient

    print("\n[WatchTower attached — dashboard updates at http://localhost:3000/dashboard]\n")

    sentinel = SentinelClient(base_url)
    graph = invoke_travel_agent  # stand-in for graph.invoke(...)

    result = await sentinel.protect(
        "travel",
        message,
        run=lambda: graph(message),
    )

    if result.blocked:
        print(f"BLOCKED — {result.threat} ({result.confidence}% confidence)")
        print("Check the dashboard: attack graph, network panel, incident report.")
    else:
        print(f"Response: {result.response}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Travel agent integration demo")
    parser.add_argument("message", nargs="?", default="Book me a flight from Bangalore to Tokyo")
    parser.add_argument("--with-watchtower", action="store_true", help="Attach SentinelAI protection")
    parser.add_argument("--base-url", default=os.getenv("WATCHTOWER_URL", "http://localhost:8000"))
    args = parser.parse_args()

    if args.with_watchtower:
        asyncio.run(run_protected(args.message, args.base_url))
    else:
        run_bare(args.message)


if __name__ == "__main__":
    main()
