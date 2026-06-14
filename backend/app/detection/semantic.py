"""Semantic intent matching — embeddings when available, TF-IDF fallback."""

from __future__ import annotations

import math
import os
import re
from collections import Counter

from .intents import BENIGN_INTENTS, INTENT_CATEGORIES

_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


def _tokenize(text: str) -> Counter:
    return Counter(_TOKEN_RE.findall(text.lower()))


def _cosine_counters(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a if k in b)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _tfidf_similarity(prompt: str, reference: str) -> float:
    return _cosine_counters(_tokenize(prompt), _tokenize(reference))


def _embed_openai(text: str) -> list[float] | None:
    if not os.getenv("OPENAI_API_KEY"):
        return None
    try:
        from openai import OpenAI

        client = OpenAI()
        model = os.getenv("OPENAI_EMBED_MODEL", "text-embedding-3-small")
        r = client.embeddings.create(input=text[:8000], model=model)
        return r.data[0].embedding
    except Exception:
        return None


def _google_api_key() -> str | None:
    return os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")


def _embed_gemini(text: str) -> list[float] | None:
    api_key = _google_api_key()
    if not api_key:
        return None
    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        model = os.getenv("GEMINI_EMBED_MODEL", "gemini-embedding-001")
        result = client.models.embed_content(model=model, contents=text[:8000])
        embeddings = result.embeddings or []
        if not embeddings:
            return None
        return embeddings[0].values
    except Exception:
        return None


def _embed_ollama(text: str) -> list[float] | None:
    import httpx

    base = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_EMBED_MODEL", os.getenv("OLLAMA_MODEL", "llama3.2"))
    try:
        r = httpx.post(
            f"{base}/api/embeddings",
            json={"model": model, "prompt": text[:8000]},
            timeout=15.0,
        )
        if r.status_code == 200:
            return r.json().get("embedding")
    except Exception:
        pass
    return None


def _cosine_vec(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def analyze_semantic(prompt: str) -> dict:
    """Return semantic scores per attack category + best match."""
    prompt_tokens = _tokenize(prompt)
    best_cat = ""
    best_sim = 0.0
    category_scores: dict[str, float] = {}

    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    prompt_emb = None
    if provider == "ollama":
        prompt_emb = _embed_ollama(prompt)
    elif provider in ("gemini", "google"):
        prompt_emb = _embed_gemini(prompt)
    if prompt_emb is None:
        prompt_emb = _embed_openai(prompt)

    for cat, examples in INTENT_CATEGORIES.items():
        tfidf_sims = [_tfidf_similarity(prompt, ex) for ex in examples]
        score = max(tfidf_sims) if tfidf_sims else 0.0

        if prompt_emb is not None and examples:
            if provider == "ollama":
                ref_emb = _embed_ollama(examples[0])
            elif provider in ("gemini", "google"):
                ref_emb = _embed_gemini(examples[0])
            else:
                ref_emb = _embed_openai(examples[0])
            if ref_emb:
                score = max(score, _cosine_vec(prompt_emb, ref_emb))

        category_scores[cat] = round(score * 100, 1)
        if score > best_sim:
            best_sim = score
            best_cat = cat

    benign_sims = [_tfidf_similarity(prompt, b) for b in BENIGN_INTENTS]
    benign_score = max(benign_sims) if benign_sims else 0.0

    # Attack intent must exceed benign baseline
    attack_margin = best_sim - benign_score
    normalized = max(0.0, min(1.0, (best_sim * 0.7 + attack_margin * 0.3)))

    signals = []
    if best_sim > 0.35:
        signals.append(f"Semantic match: {best_cat.replace('_', ' ')} ({best_sim:.0%})")
    if attack_margin > 0.15:
        signals.append(f"Attack intent exceeds benign baseline (+{attack_margin:.0%})")
    if prompt_emb is not None:
        signals.append("Embedding similarity layer active")

    return {
        "score": round(normalized * 100),
        "best_category": best_cat,
        "best_similarity": round(best_sim, 3),
        "benign_similarity": round(benign_score, 3),
        "category_scores": category_scores,
        "signals": signals,
        "embedding_used": prompt_emb is not None,
    }
