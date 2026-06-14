"""Multi-signal threat detection for AI agent prompts and tool calls."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ── Pattern libraries ────────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|earlier|system)\s+instructions?",
    r"disregard\s+(your\s+)?(instructions?|rules?|guidelines?|policy)",
    r"forget\s+(everything|all|your)\s+(you\s+)?(know|instructions?|training|tasks?|rules?)",
    r"forget\s+(all\s+)?(previous|prior)\s+(tasks?|instructions?|rules?|context)",
    r"you\s+are\s+now\s+(a\s+)?(admin|root|unrestricted|developer)",
    r"new\s+instructions?:",
    r"jailbreak|dan\s+mode|dev\s+mode",
    r"override\s+(your\s+)?(instructions?|safety|guardrails?)",
    r"pretend\s+(you\s+)?(have\s+)?no\s+(rules|restrictions|limits)",
    r"act\s+as\s+(if\s+)?(you\s+)?(have\s+)?no\s+(restrictions|limits|ethics)",
    r"act\s+as\s+a?\s+(debater|hacker|root|admin|unrestricted|evil|villain)",
    r"(new|different|great)\s+(task|challenge)\s*(for\s+you|:)",
    r"focus\s+on\s+(your\s+)?new\s+task",
    r"stop\s+[-–—]\s+.*(urgent|forget|new\s+task|ignore)",
    r"that\s+was\s+ok\s+before[,]?\s+now\s+",
    r"stay\s+in\s+(your\s+)?(role|character)\s+without",
]

INDIRECT_INJECTION_PATTERNS = [
    r"before\s+(you\s+)?(book|search|help)",
    r"first[,]?\s+(read|load|fetch|get)\s+(the\s+)?(\.env|config|secrets?|workspace)",
    r"as\s+a\s+(test|debug|verification)\s+step",
    r"for\s+(audit|compliance|debug)\s+purposes?",
    r"hidden\s+instruction",
    r"actually[,]?\s+(ignore|disregard|forget)",
]

EXFIL_PATTERNS = [
    r"webhook\.site",
    r"pastebin",
    r"requestbin",
    r"ngrok",
    r"burpcollaborator",
    r"pipedream",
    r"discord(app)?\.com/api/webhooks",
    r"hooks\.slack\.com",
    r"transfer\.sh",
    r"file\.io",
]

FILE_ACCESS_PATTERNS = [
    r"read_workspace",
    r"read\s+(any\s+)?(local\s+)?files?",
    r"read\s+/etc/",
    r"read\s+\.env",
    r"customer_records",
    r"workspace[/\\]",
    r"access\s+(the\s+)?(filesystem|workspace|secrets?)",
    r"cat\s+/etc/",
    r"open\s+(\.env|config)",
    r"load\s+(the\s+)?(\.env|secrets?|credentials?)",
]

PII_HARVEST_PATTERNS = [
    r"passport\s+(numbers?|ids?)",
    r"credit\s+card",
    r"all\s+(customer|user)\s+(emails?|data|records|pii)",
    r"dump\s+(the\s+)?(database|customers?|records?|users?)",
    r"export\s+(all\s+)?(customer|user|personal)\s+data",
    r"list\s+every\s+(email|passport|phone)",
    r"ssn|social\s+security",
]

TOOL_ABUSE_PATTERNS = [
    r"post_to_webhook",
    r"send\s+(all|the|customer|data|records|files|everything)\s+(to|via)",
    r"post\s+(all|the|customer|data|records)\s+to",
    r"upload\s+(the\s+)?(data|records|files)\s+to",
    r"email\s+(all\s+)?(records|customers?|data)\s+to",
]

SSRF_PATTERNS = [
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"metadata\.azure",
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"internal\.",
    r"192\.168\.\d",
    r"10\.\d+\.\d+\.\d+",
]

PROMPT_LEAK_PATTERNS = [
    r"(show|print|reveal|repeat|output|display)\s+(me\s+)?(all\s+)?(your\s+)?(system\s+)?prompt",
    r"what\s+(are|were)\s+your\s+(original\s+)?instructions",
    r"repeat\s+(the\s+)?(text|words)\s+above",
    r"prompt\s+texts?",
    r"(show|tell|give)\s+me\s+(all\s+)?(your\s+)?(hidden\s+)?(prompt|instruction)",
]

ENCODING_PATTERNS = [
    r"base64",
    r"rot13",
    r"\\u[0-9a-f]{4}",
    r"&#x?[0-9a-f]+;",
]

BENIGN_HOSTS = {
    "booking.com", "www.booking.com", "openai.com", "api.openai.com",
    "googleapis.com", "localhost:11434",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov"}

URL_RE = re.compile(r"https?://[^\s\)\]\"']+", re.I)


@dataclass
class ThreatAssessment:
    is_attack: bool
    confidence: int = 0
    threat: str = "None"
    risk: str = "Low"
    techniques: list[str] = field(default_factory=list)
    exfil_target: str = ""
    wants_file_access: bool = False
    signals: list[str] = field(default_factory=list)
    category: str = "benign"
    detection_layers: dict = field(default_factory=dict)
    reasoning: str = ""


def _match_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(p, text, re.I) for p in patterns)


def _extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def _is_benign_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    if host in BENIGN_HOSTS:
        return True
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return False
    return host.endswith(".com") and "webhook" not in host and "paste" not in host


def _detect_encoding_evasion(text: str) -> bool:
    if _match_any(text, ENCODING_PATTERNS):
        return True
    b64_chunks = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    for chunk in b64_chunks[:3]:
        try:
            decoded = base64.b64decode(chunk + "==", validate=False).decode("utf-8", errors="ignore").lower()
            if any(w in decoded for w in ("ignore", "webhook", ".env", "instruction")):
                return True
        except Exception:
            pass
    return False


def _pick_exfil_target(text: str) -> str:
    for url in _extract_urls(text):
        host = urlparse(url).netloc
        if host and not _is_benign_url(url):
            return host
    for pat in EXFIL_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(0).lower()
    return "external endpoint"


def _classify_threat(
    has_injection: bool,
    has_indirect: bool,
    has_exfil: bool,
    has_file: bool,
    has_pii: bool,
    has_tool_abuse: bool,
    has_ssrf: bool,
    has_prompt_leak: bool,
) -> str:
    if has_ssrf:
        return "SSRF / Cloud Metadata Probe"
    if has_injection and has_exfil:
        return "Prompt Injection + Exfiltration"
    if has_indirect and (has_file or has_exfil):
        return "Indirect Prompt Injection"
    if has_injection:
        return "Prompt Injection"
    if has_pii and has_exfil:
        return "PII Exfiltration"
    if has_pii:
        return "PII Harvesting"
    if has_tool_abuse and has_exfil:
        return "Data Exfiltration"
    if has_tool_abuse:
        return "Unauthorized Tool Use"
    if has_prompt_leak:
        return "System Prompt Extraction"
    if has_file and has_exfil:
        return "Secrets Exfiltration"
    if has_file:
        return "Sensitive File Access"
    if has_exfil:
        return "Network Exfiltration"
    return "Agent Abuse"


def assess_prompt(text: str) -> ThreatAssessment:
    """CASCADE multi-layer detection (regex + semantic + behavior + optional LLM judge)."""
    from .detection.engine import cascade_assess
    return cascade_assess(text)


def assess_tool_call(tool_name: str, args: dict) -> ThreatAssessment:
    """Second-layer: inspect tool name + arguments after LLM selects a tool."""
    args_str = str(args).lower()
    score = 0
    techniques: list[str] = []
    signals: list[str] = []

    if tool_name == "read_workspace_file":
        path = str(args.get("filepath", args.get("path", ""))).lower()
        if any(s in path for s in (".env", "secret", "credential", "customer_records", "password")):
            score += 40
            techniques.append("Sensitive File Access")
            signals.append(f"Blocked read of sensitive path: {path}")

    if tool_name == "post_to_webhook":
        url = str(args.get("url", "")).lower()
        if url and not _is_benign_url(url):
            score += 45
            techniques.append("Data Exfiltration")
            signals.append(f"Blocked POST to {url}")
        if any(k in args_str for k in ("passport", "api_key", "secret", "customer")):
            score += 20
            techniques.append("PII in Transit")
            signals.append("Payload contains sensitive field names")

    is_attack = score >= 28
    if not is_attack:
        return ThreatAssessment(is_attack=False)

    return ThreatAssessment(
        is_attack=True,
        confidence=min(99, 60 + score // 2),
        threat="Tool Call Blocked",
        risk="Critical",
        techniques=techniques,
        exfil_target=_pick_exfil_target(str(args)),
        wants_file_access=tool_name == "read_workspace_file",
        signals=signals,
        category="tool_block",
    )


def normal_agent_reply(message: str, agent_name: str) -> str:
    lower = message.lower()
    if any(w in lower for w in ("flight", "fly", "book", "tokyo", "bangalore", "travel")):
        return (
            "I found 3 flights from Bangalore (BLR) to Tokyo (NRT). "
            "Best option: ANA NH848 departing 06:45, ¥42,500."
        )
    return f"{agent_name} processed your request. All security checks passed."


def blocked_agent_reply(assessment: ThreatAssessment) -> str:
    techniques = ", ".join(assessment.techniques)
    signals_preview = "\n".join(f"  • {s}" for s in assessment.signals[:5])
    return (
        "This request was **blocked by SentinelAI**.\n\n"
        f"Threat: **{assessment.threat}** ({assessment.confidence}% confidence)\n"
        f"Risk: **{assessment.risk}**\n"
        f"Techniques: {techniques}\n\n"
        f"Signals:\n{signals_preview}\n\n"
        "Dangerous tools were **not executed**. Agent quarantined."
    )
