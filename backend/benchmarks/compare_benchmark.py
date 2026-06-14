#!/usr/bin/env python3
"""Compare CASCADE (fast + Gemini hybrid) vs HF prompt-injection classifiers."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from benchmarks.hf_benchmark import (  # noqa: E402
    SampleMetrics,
    _print_metrics,
    load_samples,
)

BASELINE_MODELS = {
    "protectai/deberta-v3-base-prompt-injection-v2": {
        "description": "ProtectAI DeBERTa — widely used ML injection classifier baseline",
        "attack_labels": {"INJECTION", "injection", "LABEL_1", "1"},
    },
    "deepset/deberta-v3-base-injection": {
        "description": "Deepset DeBERTa — trained on this dataset (strong upper bound)",
        "attack_labels": {"INJECTION", "injection", "LABEL_1", "1"},
    },
}


def _configure_cascade(mode: str, llm_enabled: bool) -> None:
    os.environ["SENTINEL_DETECTION_MODE"] = mode
    os.environ["SENTINEL_LLM_JUDGE"] = "1" if llm_enabled else "0"


def run_cascade(samples: list[tuple[str, bool]], *, offline: bool = False) -> tuple[SampleMetrics, float]:
    from app.chat_engine import assess_prompt

    saved: dict[str, str | None] = {}
    if offline:
        for key in ("LLM_PROVIDER", "GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"):
            saved[key] = os.environ.get(key)
        os.environ["LLM_PROVIDER"] = "openai"
        for key in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"):
            os.environ.pop(key, None)

    metrics = SampleMetrics()
    t0 = time.perf_counter()
    try:
        for text, expected in samples:
            predicted = assess_prompt(text).is_attack
            if expected and predicted:
                metrics.tp += 1
            elif not expected and not predicted:
                metrics.tn += 1
            elif not expected and predicted:
                metrics.fp += 1
            else:
                metrics.fn += 1
    finally:
        if offline:
            for key, val in saved.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
    elapsed = time.perf_counter() - t0
    return metrics, elapsed


class BaselineClassifier:
    def __init__(self, model_id: str, threshold: float = 0.5):
        from transformers import pipeline

        self.model_id = model_id
        self.threshold = threshold
        cfg = BASELINE_MODELS.get(model_id, {})
        self.attack_labels = cfg.get("attack_labels", {"INJECTION", "injection", "LABEL_1"})
        print(f"Loading baseline model: {model_id} ...")
        self.pipe = pipeline(
            "text-classification",
            model=model_id,
            truncation=True,
            max_length=512,
            device=-1,
        )
        labels = getattr(self.pipe.model.config, "id2label", {}) or {}
        print(f"  Labels: {labels}")

    def predict_attack(self, text: str) -> bool:
        result = self.pipe(text[:2000])[0]
        label = str(result.get("label", "")).upper()
        score = float(result.get("score", 0))
        # Some models use INJECTION/LEGIT; others use LABEL_0/LABEL_1
        if label in {x.upper() for x in self.attack_labels}:
            return score >= self.threshold
        if label in {"LEGIT", "BENIGN", "LABEL_0", "0", "SAFE"}:
            return False
        # Fallback: higher score on non-benign label → attack
        return score >= self.threshold and label not in {"LEGIT", "BENIGN", "SAFE", "LABEL_0"}


def run_sklearn_baseline(
    samples: list[tuple[str, bool]],
    test_ratio: float = 0.35,
) -> tuple[SampleMetrics, float]:
    """Simple TF-IDF + LogisticRegression — typical lightweight ML baseline."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split

    texts = [t for t, _ in samples]
    labels = [1 if a else 0 for _, a in samples]
    if len(set(labels)) < 2 or len(samples) < 20:
        raise ValueError("Need balanced samples >= 20 for sklearn baseline")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_ratio, random_state=42, stratify=labels
    )
    t0 = time.perf_counter()
    vec = TfidfVectorizer(max_features=8000, ngram_range=(1, 2))
    Xtr = vec.fit_transform(X_train)
    Xte = vec.transform(X_test)
    clf = LogisticRegression(max_iter=500, class_weight="balanced")
    clf.fit(Xtr, y_train)
    preds = clf.predict(Xte)
    elapsed = time.perf_counter() - t0

    metrics = SampleMetrics()
    for expected, predicted in zip(y_test, preds):
        exp, pred = bool(expected), bool(predicted)
        if exp and pred:
            metrics.tp += 1
        elif not exp and not pred:
            metrics.tn += 1
        elif not exp and pred:
            metrics.fp += 1
        else:
            metrics.fn += 1
    return metrics, elapsed


def run_baseline(
    samples: list[tuple[str, bool]],
    model_id: str,
    threshold: float,
) -> tuple[SampleMetrics, float]:
    clf = BaselineClassifier(model_id, threshold=threshold)
    metrics = SampleMetrics()
    t0 = time.perf_counter()
    for text, expected in samples:
        predicted = clf.predict_attack(text)
        if expected and predicted:
            metrics.tp += 1
        elif not expected and not predicted:
            metrics.tn += 1
        elif not expected and predicted:
            metrics.fp += 1
        else:
            metrics.fn += 1
    elapsed = time.perf_counter() - t0
    return metrics, elapsed


def _comparison_table(rows: list[dict]) -> str:
    header = f"{'Detector':<42} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Time':>8}"
    lines = [header, "-" * len(header)]
    for row in rows:
        m = row["metrics"]
        lines.append(
            f"{row['name']:<42} "
            f"{m['accuracy']:>6.1%} "
            f"{m['precision']:>6.1%} "
            f"{m['recall']:>6.1%} "
            f"{m['f1']:>6.1%} "
            f"{row['elapsed_s']:>7.1f}s"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare CASCADE vs HF injection classifiers")
    parser.add_argument("--dataset", default="deepset/prompt-injections")
    parser.add_argument("--split", default=None)
    parser.add_argument("--max-samples", "--limit", type=int, default=100, dest="max_samples")
    parser.add_argument(
        "--baseline",
        default="sklearn-tfidf",
        choices=["sklearn-tfidf", *BASELINE_MODELS.keys()],
        help="Baseline detector (sklearn-tfidf=local ML, or HF transformer model)",
    )
    parser.add_argument("--baseline-threshold", type=float, default=0.5)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--skip-gemini", action="store_true", help="Skip Gemini hybrid (no API key)")
    parser.add_argument("--llm-provider", default=None, help="Override LLM_PROVIDER for CASCADE hybrid")
    parser.add_argument("--output", type=Path, default=Path("benchmarks/results_comparison.json"))
    args = parser.parse_args()

    if args.llm_provider:
        os.environ["LLM_PROVIDER"] = args.llm_provider

    samples = load_samples(args.dataset, args.split, args.max_samples)
    print(f"Dataset: {args.dataset}  samples={len(samples)}")
    print()

    results: list[dict] = []

    # 1) CASCADE fast (regex + semantic, no LLM)
    _configure_cascade("fast", llm_enabled=False)
    fast_metrics, fast_time = run_cascade(samples, offline=True)
    _print_metrics("CASCADE fast (regex + semantic, offline)", fast_metrics)
    results.append(
        {
            "name": "CASCADE fast (offline)",
            "detector": "cascade_fast",
            "metrics": fast_metrics.to_dict(),
            "elapsed_s": round(fast_time, 2),
            "config": {"SENTINEL_DETECTION_MODE": "fast", "SENTINEL_LLM_JUDGE": "0"},
        }
    )

    # 2) ML baseline classifier
    if not args.skip_baseline:
        if args.baseline == "sklearn-tfidf":
            baseline_metrics, baseline_time = run_sklearn_baseline(samples)
            baseline_name = "Baseline: TF-IDF + LogisticRegression"
            baseline_meta = {"detector": "sklearn_tfidf", "test_ratio": 0.35}
        else:
            baseline_metrics, baseline_time = run_baseline(
                samples, args.baseline, args.baseline_threshold
            )
            baseline_name = f"Baseline: {args.baseline.split('/')[-1]}"
            baseline_meta = {
                "detector": "hf_classifier",
                "model": args.baseline,
                "threshold": args.baseline_threshold,
            }
        _print_metrics(baseline_name, baseline_metrics)
        results.append(
            {
                "name": baseline_name,
                **baseline_meta,
                "metrics": baseline_metrics.to_dict(),
                "elapsed_s": round(baseline_time, 2),
            }
        )

    # 3) CASCADE hybrid + LLM (Gemini recommended)
    if not args.skip_gemini:
        provider = os.environ.get("LLM_PROVIDER", "openai")
        if provider in ("gemini", "google") and not (
            os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        ):
            print("\nSkipping CASCADE hybrid: GOOGLE_API_KEY not set")
        else:
            if args.llm_provider:
                os.environ["LLM_PROVIDER"] = args.llm_provider
            _configure_cascade("hybrid", llm_enabled=True)
            print(f"\nRunning CASCADE hybrid (LLM_PROVIDER={provider}) — may take several minutes...")
            hybrid_metrics, hybrid_time = run_cascade(samples)
            hybrid_name = f"CASCADE hybrid + {provider}"
            _print_metrics(hybrid_name, hybrid_metrics)
            results.append(
                {
                    "name": hybrid_name,
                    "detector": "cascade_hybrid",
                    "metrics": hybrid_metrics.to_dict(),
                    "elapsed_s": round(hybrid_time, 2),
                    "config": {
                        "SENTINEL_DETECTION_MODE": "hybrid",
                        "SENTINEL_LLM_JUDGE": "1",
                        "LLM_PROVIDER": provider,
                    },
                }
            )

    # Literature reference (full deepset test set, Sentinel paper 2025)
    results.append(
        {
            "name": "Reference: ProtectAI DeBERTa-v2 (published)",
            "detector": "literature",
            "source": "https://arxiv.org/abs/2506.05446 Table 2 — deepset/prompt-injections F1",
            "metrics": {
                "f1": 0.536,
                "note": "Full dataset; not re-run locally — industry ML classifier baseline",
            },
            "elapsed_s": None,
        }
    )

    live_rows = [r for r in results if isinstance(r.get("metrics", {}).get("accuracy"), (int, float))]
    print("\n" + "=" * 72)
    print("COMPARISON SUMMARY (live runs)")
    print("=" * 72)
    print(_comparison_table(live_rows))
    ref = [r for r in results if r.get("detector") == "literature"]
    if ref:
        print("\nPublished baseline (full deepset, Sentinel paper 2025):")
        for r in ref:
            print(f"  {r['name']}: F1 ≈ {r['metrics']['f1']:.1%}  ({r['source']})")

    payload = {
        "dataset": args.dataset,
        "max_samples": args.max_samples,
        "sample_count": len(samples),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))
    print(f"\nResults written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
