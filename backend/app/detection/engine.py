"""CASCADE — Cascading Agent Security Analysis: regex + semantic + behavior + LLM judge."""

from __future__ import annotations

import os
import re

from ..chat_engine import (
    ThreatAssessment,
    _classify_threat,
    _match_any,
    _pick_exfil_target,
    FILE_ACCESS_PATTERNS,
    EXFIL_PATTERNS,
    INJECTION_PATTERNS,
    INDIRECT_INJECTION_PATTERNS,
    PII_HARVEST_PATTERNS,
    PROMPT_LEAK_PATTERNS,
    SSRF_PATTERNS,
    TOOL_ABUSE_PATTERNS,
    _detect_encoding_evasion,
    _is_benign_url,
    _extract_urls,
)

from .behavior import analyze_behavior
from .llm_agent import security_agent_assess
from .semantic import analyze_semantic

# Re-use regex scoring logic inline for layer 1
_REGEX_WEIGHTS = {
    "injection": (35, "Instruction Override", INJECTION_PATTERNS),
    "indirect": (30, "Indirect Injection", INDIRECT_INJECTION_PATTERNS),
    "file": (28, "Sensitive File Access", FILE_ACCESS_PATTERNS),
    "pii": (32, "PII Harvesting", PII_HARVEST_PATTERNS),
    "tool_abuse": (30, "Tool Abuse", TOOL_ABUSE_PATTERNS),
    "ssrf": (45, "SSRF", SSRF_PATTERNS),
    "prompt_leak": (25, "Prompt Leakage", PROMPT_LEAK_PATTERNS),
}


def _regex_layer(text: str) -> dict:
    score = 0
    techniques: list[str] = []
    signals: list[str] = []
    flags: dict[str, bool] = {}

    for key, (pts, technique, patterns) in _REGEX_WEIGHTS.items():
        hit = _match_any(text, patterns)
        flags[key] = hit
        if hit:
            score += pts
            techniques.append(technique)
            signals.append(f"Pattern: {technique}")

    flags["encoding"] = _detect_encoding_evasion(text)
    if flags["encoding"]:
        score += 20
        techniques.append("Evasion")
        signals.append("Encoding/obfuscation detected")

    urls = _extract_urls(text)
    flags["exfil"] = bool([u for u in urls if not _is_benign_url(u)]) or _match_any(text, EXFIL_PATTERNS)
    if flags["exfil"]:
        score += 30
        techniques.append("Data Exfiltration")
        signals.append("Suspicious egress destination")

    if flags.get("file") and flags.get("exfil"):
        score += 15
        signals.append("Composite: file + exfil patterns")
    if len(techniques) >= 3:
        score += 10

    return {
        "score": min(100, score),
        "techniques": techniques,
        "signals": signals,
        "flags": flags,
    }


_CATEGORY_THREAT = {
    "instruction_override": "Prompt Injection",
    "indirect_injection": "Indirect Prompt Injection",
    "secrets_exfil": "Secrets Exfiltration",
    "pii_harvest": "PII Exfiltration",
    "tool_chain_abuse": "Unauthorized Tool Use",
    "ssrf_probe": "SSRF / Cloud Metadata Probe",
    "prompt_extraction": "System Prompt Extraction",
}

_INJECTION_CATEGORIES = frozenset({
    "instruction_override",
    "indirect_injection",
    "prompt_extraction",
})


def _detection_mode() -> str:
    return os.getenv("SENTINEL_DETECTION_MODE", "hybrid").lower()


def _llm_agent_enabled() -> bool:
    return os.getenv("SENTINEL_LLM_JUDGE", "1") != "0"


def _should_invoke_agent(
    mode: str,
    fused: float,
    regex: dict,
    semantic: dict,
    behavior: dict,
    prompt: str,
) -> bool:
    if not _llm_agent_enabled():
        return False
    if mode == "fast":
        return False
    if mode == "agent":
        return True

    # hybrid — escalate unless clearly benign travel-only request
    clearly_benign = (
        fused < 8
        and regex["score"] == 0
        and behavior["score"] == 0
        and semantic.get("score", 0) < 12
        and semantic.get("best_category") not in _INJECTION_CATEGORIES
    )
    if clearly_benign:
        return False

    # Gray zone — suspicious but fast path did not block
    if 12 <= fused < 32:
        return True
    if semantic.get("score", 0) >= 22 and semantic.get("best_category") in _INJECTION_CATEGORIES:
        return True
    if regex["score"] >= 20:
        return True
    if behavior["score"] >= 25:
        return True
    if re.search(r"\b(stop|forget|ignore|disregard|act as|new task|prompt)\b", prompt, re.I):
        return True
    # Already blocked by fast path — optional agent for richer reasoning only
    if fused >= 32 and os.getenv("SENTINEL_AGENT_ON_BLOCK", "0") == "1":
        return True
    return False


def _build_agent_context(regex: dict, semantic: dict, behavior: dict, fused: float) -> dict:
    return {
        "regex_score": regex["score"],
        "regex_flags": regex["flags"],
        "regex_techniques": regex["techniques"],
        "semantic_score": semantic["score"],
        "semantic_category": semantic.get("best_category"),
        "behavior_score": behavior["score"],
        "predicted_tools": behavior.get("predicted_tools", []),
        "fused_prescore": round(fused, 1),
    }


def cascade_assess(prompt: str) -> ThreatAssessment:
    """Multi-layer agent threat analysis."""
    if not prompt.strip():
        return ThreatAssessment(is_attack=False)

    regex = _regex_layer(prompt)
    semantic = analyze_semantic(prompt)
    behavior = analyze_behavior(prompt)

    # Weighted fusion (regex alone is only 25%)
    w_regex, w_sem, w_beh = 0.25, 0.35, 0.30
    fused = regex["score"] * w_regex + semantic["score"] * w_sem + behavior["score"] * w_beh

    # Generic injection often fires one layer moderately — boost when intent is clear
    regex_flags = regex["flags"]
    inj_regex = regex_flags.get("injection") or regex_flags.get("prompt_leak")
    inj_sem = semantic["best_category"] in _INJECTION_CATEGORIES and semantic["score"] >= 28
    if inj_regex or inj_sem:
        injection_fused = (
            regex["score"] * 0.40
            + semantic["score"] * 0.45
            + behavior["score"] * 0.15
        )
        fused = max(fused, injection_fused)
    if inj_regex and semantic["score"] >= 25:
        fused = max(fused, 38.0)
    if semantic["score"] >= 42 and semantic["best_category"] in _INJECTION_CATEGORIES:
        fused = max(fused, 45.0)

    mode = _detection_mode()
    agent_result = None
    invoke_agent = _should_invoke_agent(mode, fused, regex, semantic, behavior, prompt)

    if invoke_agent:
        agent_result = security_agent_assess(
            prompt,
            context=_build_agent_context(regex, semantic, behavior, fused),
        )
        if agent_result:
            if mode == "agent":
                # Agent-primary: LLM verdict drives the decision
                fused = agent_result["score"]
                if agent_result["is_attack"]:
                    fused = max(fused, 55.0)
            elif agent_result["is_attack"]:
                fused = max(fused, fused * 0.30 + agent_result["score"] * 0.70)
            else:
                # Agent says benign — dampen false positives from weak pattern hits
                fused = min(fused, fused * 0.65 + agent_result["score"] * 0.35)

    llm_result = agent_result

    all_signals = regex["signals"] + semantic["signals"] + behavior["signals"]
    all_techniques = list(dict.fromkeys(regex["techniques"]))

    if semantic["best_category"]:
        cat = semantic["best_category"]
        if semantic["score"] >= 40 and cat in _CATEGORY_THREAT:
            label = _CATEGORY_THREAT[cat]
            if label not in all_techniques:
                all_techniques.append(label)

    if llm_result:
        all_signals.extend(llm_result.get("signals", []))
        for t in llm_result.get("techniques", []):
            if t not in all_techniques:
                all_techniques.append(t)

    flags = regex["flags"]
    is_attack = fused >= 32

    # LLM agent can block independently when confident (even if fast fused < 32)
    if agent_result and agent_result.get("is_attack") and agent_result["score"] >= 65:
        is_attack = True
        fused = max(fused, agent_result["score"])
    elif agent_result and agent_result.get("is_attack"):
        if mode == "agent" and agent_result["score"] >= 50:
            is_attack = True
            fused = max(fused, agent_result["score"])
        elif agent_result["score"] >= 65:
            is_attack = True
            fused = max(fused, agent_result["score"])
    elif agent_result and not agent_result.get("is_attack") and agent_result["score"] >= 70:
        # High-confidence benign from agent — reduce false positives
        is_attack = False
        fused = min(fused, 20.0)
    elif agent_result and not agent_result.get("is_attack") and agent_result["score"] >= 75 and mode == "agent":
        is_attack = False
        fused = min(fused, 25.0)

    layers = {
        "regex": regex["score"],
        "semantic": semantic["score"],
        "behavior": behavior["score"],
        "llm_agent": agent_result["score"] if agent_result else None,
        "llm_judge": agent_result["score"] if agent_result else None,
        "fused": round(fused, 1),
        "semantic_category": semantic["best_category"],
        "predicted_tools": behavior["predicted_tools"],
        "embedding_used": semantic["embedding_used"],
        "detection_mode": mode,
        "agent_invoked": invoke_agent,
    }

    if not is_attack:
        return ThreatAssessment(
            is_attack=False,
            signals=["CASCADE: fused score below threshold"] + all_signals[:3],
            category="benign",
            detection_layers=layers,
        )

    confidence = min(99, int(50 + fused * 0.45 + min(12, len(all_techniques) * 4)))
    risk = "Critical" if fused >= 70 or flags.get("ssrf") else "High" if fused >= 45 else "Medium"

    threat = _classify_threat(
        flags.get("injection", False),
        flags.get("indirect", False),
        flags.get("exfil", False),
        flags.get("file", False),
        flags.get("pii", False),
        flags.get("tool_abuse", False),
        flags.get("ssrf", False),
        flags.get("prompt_leak", False),
    )
    if llm_result and llm_result.get("threat"):
        threat = llm_result["threat"].replace("_", " ").title()

    reasoning = llm_result.get("reasoning", "") if llm_result else ""
    if llm_result and llm_result.get("predicted_tools"):
        tools = ", ".join(llm_result["predicted_tools"])
        reasoning = (reasoning + f" | Agent predicted tools: {tools}").strip(" |")
    if behavior.get("chain"):
        reasoning = (reasoning + " | " + behavior["chain"]).strip(" |")

    return ThreatAssessment(
        is_attack=True,
        confidence=confidence,
        threat=threat,
        risk=risk,
        techniques=all_techniques or ["Agent Abuse"],
        exfil_target=_pick_exfil_target(prompt),
        wants_file_access=flags.get("file", False) or "read_workspace_file" in behavior["predicted_tools"],
        signals=all_signals,
        category=threat.lower().replace(" ", "_"),
        detection_layers=layers,
        reasoning=reasoning,
    )
