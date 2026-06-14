"""Predict intended tool chain from prompt — agent-behavior analysis without regex-only matching."""

from __future__ import annotations

import re

# Map prompt evidence → tools the agent would likely invoke
TOOL_SIGNATURES: dict[str, dict] = {
    "search_flights": {
        "weight": 5,
        "patterns": [r"\bflight", r"\bfly\b", r"\bbook\b.*\b(to|from)\b", r"\bblr\b", r"\btokyo\b"],
    },
    "search_hotels": {
        "weight": 5,
        "patterns": [r"\bhotel", r"\bstay\b", r"\broom\b"],
    },
    "read_workspace_file": {
        "weight": 35,
        "patterns": [
            r"read_workspace", r"\b\.env\b", r"customer_records", r"workspace",
            r"read\s+(the\s+)?(local\s+)?files?", r"config\s+file", r"secrets?",
            r"environment\s+variables?", r"load\s+(the\s+)?env",
        ],
    },
    "post_to_webhook": {
        "weight": 40,
        "patterns": [
            r"post_to_webhook", r"webhook\.site", r"pastebin", r"https?://",
            r"post\s+(all|the|data|records)", r"upload\s+to", r"send\s+to\s+http",
            r"upload\s+(them|it|data|elsewhere)", r"send\s+(them|it|data)\s+(to|elsewhere)",
        ],
    },
}

RISK_CHAINS: list[tuple[frozenset[str], int, str]] = [
    (frozenset({"read_workspace_file", "post_to_webhook"}), 95, "Read secrets → exfiltrate"),
    (frozenset({"read_workspace_file"}), 55, "Sensitive file access"),
    (frozenset({"post_to_webhook"}), 50, "Unauthorized network egress"),
]


def analyze_behavior(prompt: str) -> dict:
    lower = prompt.lower()
    predicted: list[str] = []
    score = 0
    signals: list[str] = []

    for tool, meta in TOOL_SIGNATURES.items():
        if any(re.search(p, lower) for p in meta["patterns"]):
            predicted.append(tool)
            score += meta["weight"]

    predicted_set = frozenset(predicted)
    chain_label = ""
    for chain_tools, chain_score, label in RISK_CHAINS:
        if chain_tools.issubset(predicted_set):
            score = max(score, chain_score)
            chain_label = label
            signals.append(f"Predicted tool chain: {label}")

    if predicted:
        signals.append(f"Likely tools: {', '.join(predicted)}")

    # SSRF in URL targets internal IPs
    if re.search(r"169\.254\.169\.254|metadata\.|localhost|127\.0\.0\.1", lower):
        score = max(score, 80)
        signals.append("Internal/metadata URL in egress path")

    return {
        "score": min(100, score),
        "predicted_tools": predicted,
        "chain": chain_label,
        "signals": signals,
    }
