#!/usr/bin/env python3
"""Benchmark CASCADE detection against Hugging Face prompt-injection datasets."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Disable LLM judge by default for reproducible offline runs.
os.environ.setdefault("SENTINEL_LLM_JUDGE", "0")

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.chat_engine import assess_prompt  # noqa: E402
from app.detection.engine import cascade_assess  # noqa: E402 — layer scores on benign path

DATASET_CONFIGS = {
    "deepset/prompt-injections": {
        "text_field": "text",
        "label_field": "label",
        "attack_values": {1, "1", True},
        "benign_values": {0, "0", False},
        "default_split": None,
        "description": "662 labeled prompts (train/test); classic injection benchmark",
    },
    "Lakera/gandalf_ignore_instructions": {
        "text_field": "text",
        "label_field": None,
        "attack_values": None,
        "benign_values": None,
        "attack_only": True,
        "default_split": "train",
        "description": "1000 Gandalf ignore-instruction attacks (no benign labels)",
    },
}

LAYER_NAMES = ("regex", "semantic", "behavior", "llm_agent", "fused")


@dataclass
class SampleMetrics:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def confusion_matrix(self) -> str:
        return (
            f"                 Predicted\n"
            f"                 Attack   Benign\n"
            f"Actual Attack    {self.tp:5d}    {self.fn:5d}\n"
            f"       Benign    {self.fp:5d}    {self.tn:5d}"
        )

    def to_dict(self) -> dict:
        return {
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "accuracy": round(self.accuracy(), 4),
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "f1": round(self.f1(), 4),
        }


@dataclass
class LayerAverages:
    blocked: dict[str, list[float]] = field(default_factory=lambda: {n: [] for n in LAYER_NAMES})
    allowed: dict[str, list[float]] = field(default_factory=lambda: {n: [] for n in LAYER_NAMES})

    def record(self, predicted_attack: bool, layers: dict) -> None:
        bucket = self.blocked if predicted_attack else self.allowed
        for name in LAYER_NAMES:
            score = layers.get(name)
            if score is not None:
                bucket[name].append(float(score))

    def summary(self) -> dict:
        out: dict = {"blocked": {}, "allowed": {}}
        for label, bucket in (("blocked", self.blocked), ("allowed", self.allowed)):
            for name, scores in bucket.items():
                if scores:
                    out[label][name] = round(sum(scores) / len(scores), 2)
        return out


def _is_attack_label(label, attack_values: set, benign_values: set) -> bool:
    if label in attack_values:
        return True
    if label in benign_values:
        return False
    raise ValueError(f"Unexpected label value: {label!r}")


def _layer_would_block(score: float | None, threshold: float = 32.0) -> bool:
    return score is not None and score >= threshold


def load_samples(dataset_name: str, split: str | None, limit: int | None) -> list[tuple[str, bool]]:
    from datasets import load_dataset

    cfg = DATASET_CONFIGS[dataset_name]
    effective_split = split if split is not None else cfg.get("default_split")
    ds = load_dataset(dataset_name, split=effective_split) if effective_split else load_dataset(dataset_name)
    if hasattr(ds, "keys"):
        rows = []
        for part in ds.values():
            rows.extend(part)
    else:
        rows = list(ds)

    if limit:
        rows = rows[:limit]

    samples: list[tuple[str, bool]] = []
    if cfg.get("attack_only"):
        for row in rows:
            text = row[cfg["text_field"]]
            if text and str(text).strip():
                samples.append((str(text), True))
        return samples

    attack_values = cfg["attack_values"]
    benign_values = cfg["benign_values"]
    label_field = cfg["label_field"]
    for row in rows:
        text = row[cfg["text_field"]]
        if not text or not str(text).strip():
            continue
        is_attack = _is_attack_label(row[label_field], attack_values, benign_values)
        samples.append((str(text), is_attack))
    return samples


def run_benchmark(
    dataset_name: str,
    split: str | None,
    limit: int | None,
) -> tuple[SampleMetrics, dict[str, SampleMetrics], LayerAverages, list[dict]]:
    samples = load_samples(dataset_name, split, limit)
    overall = SampleMetrics()
    layer_metrics = {name: SampleMetrics() for name in LAYER_NAMES}
    layer_avgs = LayerAverages()
    misclassified: list[dict] = []

    for text, expected_attack in samples:
        assessment = assess_prompt(text)
        predicted_attack = assessment.is_attack

        # cascade_assess always computes layer scores (assess_prompt omits layers on benign)
        full = cascade_assess(text)
        layer_scores = full.detection_layers or {}

        layer_avgs.record(predicted_attack, layer_scores)

        if expected_attack and predicted_attack:
            overall.tp += 1
        elif not expected_attack and not predicted_attack:
            overall.tn += 1
        elif not expected_attack and predicted_attack:
            overall.fp += 1
            misclassified.append(
                {
                    "type": "fp",
                    "text": text[:200],
                    "fused": layer_scores.get("fused"),
                    "threat": assessment.threat,
                }
            )
        else:
            overall.fn += 1
            misclassified.append(
                {
                    "type": "fn",
                    "text": text[:200],
                    "fused": layer_scores.get("fused"),
                    "layers": layer_scores,
                }
            )

        for layer_name in layer_metrics:
            score = layer_scores.get(layer_name)
            layer_pred = _layer_would_block(score)
            m = layer_metrics[layer_name]
            if expected_attack and layer_pred:
                m.tp += 1
            elif not expected_attack and not layer_pred:
                m.tn += 1
            elif not expected_attack and layer_pred:
                m.fp += 1
            else:
                m.fn += 1

    return overall, layer_metrics, layer_avgs, misclassified


def _print_metrics(title: str, m: SampleMetrics) -> None:
    print(f"\n{title}")
    print(f"  Samples:   {m.total}")
    print(f"  Accuracy:  {m.accuracy():.1%}")
    print(f"  Precision: {m.precision():.1%}")
    print(f"  Recall:    {m.recall():.1%}")
    print(f"  F1:        {m.f1():.1%}")
    print(m.confusion_matrix())


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark CASCADE on Hugging Face datasets")
    parser.add_argument(
        "--dataset",
        default="deepset/prompt-injections",
        choices=list(DATASET_CONFIGS),
        help="HF dataset to evaluate",
    )
    parser.add_argument(
        "--split",
        default=None,
        help="Dataset split (default: all splits for deepset, train for Gandalf)",
    )
    parser.add_argument(
        "--max-samples",
        "--limit",
        type=int,
        default=None,
        dest="max_samples",
        help="Max samples to evaluate",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write JSON results",
    )
    parser.add_argument("--show-errors", type=int, default=5, help="Print N misclassified examples")
    parser.add_argument(
        "--detection-mode",
        choices=("fast", "hybrid", "agent"),
        default=None,
        help="SENTINEL_DETECTION_MODE override (fast=regex/semantic only, hybrid=default, agent=LLM-primary)",
    )
    args = parser.parse_args()

    if args.detection_mode:
        os.environ["SENTINEL_DETECTION_MODE"] = args.detection_mode

    print(f"Dataset: {args.dataset}")
    print(f"Description: {DATASET_CONFIGS[args.dataset]['description']}")
    print(f"SENTINEL_LLM_JUDGE={os.environ.get('SENTINEL_LLM_JUDGE', '1')}")
    print(f"SENTINEL_DETECTION_MODE={os.environ.get('SENTINEL_DETECTION_MODE', 'hybrid')}")
    print("CASCADE block threshold: fused >= 32")

    overall, layer_metrics, layer_avgs, errors = run_benchmark(
        args.dataset, args.split, args.max_samples
    )

    _print_metrics("CASCADE (assess_prompt)", overall)
    print("\nPer-layer baselines (score >= 32, no fusion):")
    for name, metrics in layer_metrics.items():
        _print_metrics(f"  {name}", metrics)

    avg_summary = layer_avgs.summary()
    if avg_summary.get("blocked") or avg_summary.get("allowed"):
        print("\nPer-layer score averages (mean):")
        for bucket in ("blocked", "allowed"):
            if avg_summary.get(bucket):
                parts = ", ".join(f"{k}={v}" for k, v in avg_summary[bucket].items())
                print(f"  {bucket}: {parts}")

    if args.show_errors and errors:
        print(f"\nMisclassified examples (showing up to {args.show_errors}):")
        for err in errors[: args.show_errors]:
            print(f"  [{err['type']}] fused={err.get('fused')} | {err['text']!r}")

    result = {
        "dataset": args.dataset,
        "split": args.split,
        "max_samples": args.max_samples,
        "sentinel_llm_judge": os.environ.get("SENTINEL_LLM_JUDGE", "1"),
        "threshold": 32,
        "cascade": overall.to_dict(),
        "per_layer": {name: m.to_dict() for name, m in layer_metrics.items()},
        "layer_score_averages": avg_summary,
        "misclassified_count": len(errors),
    }

    if args.output:
        args.output.write_text(json.dumps(result, indent=2))
        print(f"\nResults written to {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
