"""Backend bridge to the shared travel agent in examples/travel-agent/."""

from __future__ import annotations

import sys
from pathlib import Path

_EXAMPLE_DIR = Path(__file__).resolve().parents[3] / "examples" / "travel-agent"
if str(_EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(_EXAMPLE_DIR))

from travel_agent import invoke_graph, build_travel_graph  # noqa: E402


def invoke_travel_agent(message: str) -> dict:
    graph = build_travel_graph(unprotected=False)
    return invoke_graph(graph, message)
