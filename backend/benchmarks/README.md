# CASCADE Hugging Face Benchmarks

Evaluate WatchTower's CASCADE detector (`assess_prompt`) against public prompt-injection datasets.

## Datasets

| Dataset | Size | Labels | Why use it |
|---------|------|--------|------------|
| **deepset/prompt-injections** (default) | 662 | `label` 0=benign, 1=attack | Small, balanced, widely used for injection classifiers; good first benchmark |
| Lakera/gandalf_ignore_instructions | ~1000 | attack-only | Real user jailbreak attempts from Gandalf; use for attack recall only |

Other datasets considered but not wired in yet:

- **Lakera PINT** — best-in-class benchmark, but the full labeled set is not public (evaluation harness only).
- **Agent tool-abuse** — no standard HF corpus; CASCADE's strength is agent-specific patterns (webhooks, `.env`, tool chains), which generic injection sets under-represent.

## Setup

```bash
cd backend
source .venv/bin/activate
pip install -r requirements-benchmark.txt
```

## Detection modes

| Mode | Env | Behavior |
|------|-----|----------|
| **hybrid** (default) | `SENTINEL_DETECTION_MODE=hybrid` | Fast scan + **LLM security agent** on suspicious prompts |
| **agent** | `SENTINEL_DETECTION_MODE=agent` | LLM agent is primary (best on HF benchmarks; needs API key or Ollama) |
| **fast** | `SENTINEL_DETECTION_MODE=fast` | Regex + semantic only — offline baseline |

Disable LLM entirely: `export SENTINEL_LLM_JUDGE=0`

## Run

Full deepset dataset (train + test):

```bash
python benchmarks/hf_benchmark.py
```

Quick smoke test (fast mode, no LLM):

```bash
SENTINEL_LLM_JUDGE=0 SENTINEL_DETECTION_MODE=fast python benchmarks/hf_benchmark.py --max-samples 100
```

LLM agent mode (needs OpenAI key or Ollama):

```bash
SENTINEL_DETECTION_MODE=agent LLM_PROVIDER=ollama python benchmarks/hf_benchmark.py --max-samples 50 --detection-mode agent
```

Gandalf attacks only (reports recall-style metrics; all samples are attacks):

```bash
python benchmarks/hf_benchmark.py --dataset Lakera/gandalf_ignore_instructions --split train
```

## Metrics

- **CASCADE**: `assess_prompt(text).is_attack` vs ground-truth label (block when fused score ≥ 32).
- **Per-layer baselines**: each layer score ≥ 32 treated as a block (regex, semantic, behavior, fused) — useful to see which layer drives TP/FP.

## Comparison benchmark (CASCADE vs baselines)

Run side-by-side evaluation on the same deepset samples:

```bash
cd backend
export HF_HOME=$PWD/.hf_cache
export GOOGLE_API_KEY=your-key-here
export LLM_PROVIDER=gemini

python benchmarks/compare_benchmark.py --max-samples 100 --llm-provider gemini
```

Compares:
| Detector | Description |
|----------|-------------|
| **CASCADE fast** | Regex + semantic (offline, ~0.1s) |
| **CASCADE hybrid + Gemini** | Fast scan + LLM agent on gray-zone prompts |
| **TF-IDF + LogisticRegression** | Typical lightweight ML baseline (train/test split) |
| **ProtectAI DeBERTa-v2** | Published F1 on full deepset ([Sentinel paper](https://arxiv.org/abs/2506.05446)) |

### Results (deepset/prompt-injections, n=100, live run)

| Detector | Accuracy | Precision | Recall | F1 | Time |
|----------|----------|-----------|--------|-----|------|
| CASCADE fast | 92.0% | 100% | 46.7% | **63.6%** | 0.3s |
| TF-IDF + LogReg | 94.3% | 100% | 60.0% | **75.0%** | 0.1s |
| **CASCADE hybrid + Gemini** | **98.0%** | **93.3%** | **93.3%** | **93.3%** | ~13 min |
| ProtectAI DeBERTa-v2 *(published, full 662)* | — | — | — | **53.6%** | ~0.03s/sample |

**Takeaways:**
- Offline CASCADE (fast) beats published ProtectAI DeBERTa F1 on this sample (63.6% vs 53.6%) but misses subtle paraphrased injections (46.7% recall).
- Simple TF-IDF + LogReg is a strong lightweight baseline (F1 75%) on this dataset.
- **CASCADE hybrid + Gemini** adds an LLM security agent for gray-zone prompts → **F1 93.3%**, at the cost of latency (~7s/prompt when agent fires).
- WatchTower’s agent-aware value: same stack also catches **tool-chain abuse** (webhooks, `.env`) that generic classifiers ignore — not measured by deepset.

Refresh: `python benchmarks/compare_benchmark.py --max-samples 100 --llm-provider gemini`

## Results (deepset/prompt-injections, SENTINEL_LLM_JUDGE=0)

Run `python benchmarks/hf_benchmark.py` to refresh. Last run summary is recorded below after benchmarking.

<!-- RESULTS_START -->
*(Run benchmark to populate)*
<!-- RESULTS_END -->

## Limitations

- **Domain mismatch**: deepset/Gandalf focus on generic injection/jailbreak text, not travel-agent tool abuse (webhooks, workspace files, PII exfil chains).
- **No tool-call evaluation**: this script tests prompt-level `assess_prompt` only, not `assess_tool_call`.
- **Semantic layer**: uses TF-IDF intent matching offline unless `OPENAI_API_KEY` or Ollama embeddings are configured.
- **Imbalanced real traffic**: production agents see mostly benign prompts; accuracy on balanced benchmarks overstates false-positive risk in deployment.

## What CASCADE catches vs misses

**Catches well**: explicit instruction overrides, DAN/jailbreak phrasing, exfil URLs (`webhook.site`, paste services), file/secret access language, SSRF probes, multi-signal paraphrases that match semantic intent corpus.

**May miss**: subtle indirect injection without tool/exfil cues, attacks phrased as purely benign travel questions, novel jailbreaks with no overlap to regex or intent references.
