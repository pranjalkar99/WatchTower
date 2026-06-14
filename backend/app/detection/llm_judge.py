"""Legacy LLM judge — delegates to the security agent."""

from __future__ import annotations

from .llm_agent import security_agent_assess


def llm_judge(prompt: str) -> dict | None:
    """Backward-compatible single-shot judge (no fast-layer context)."""
    return security_agent_assess(prompt, context=None)
