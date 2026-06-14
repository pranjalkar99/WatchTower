# Real Demo Runbook

## Agent capabilities (why WatchTower matters)

The travel agent has **real dangerous tools**:

| Tool | Risk |
|------|------|
| `read_workspace_file` | Reads `.env` (API keys) + `customer_records.json` (PII) |
| `post_to_webhook` | POSTs data to **any URL** (real HTTP) |
| `search_flights` / `search_hotels` | Benign |

Without WatchTower, attack prompts **execute these tools**.  
With WatchTower, prompts are blocked **before** tools run.

## CASCADE detection (vs regex-only / LlamaGuard)

WatchTower uses **CASCADE** — Cascading Agent Security Analysis:

| Layer | Weight | What it catches |
|-------|--------|-----------------|
| **Pattern** | 25% | Known injection/exfil/SSRF regex signals |
| **Semantic** | 35% | Intent similarity vs attack corpus (TF-IDF + optional embeddings) |
| **Behavior** | 30% | Predicted tool chain (`read_workspace_file` → `post_to_webhook`) |
| **LLM agent** | up to 70% in hybrid/agent mode | Contextual security analyst — catches paraphrased jailbreaks regex misses |

### Detection modes

```bash
# Default — fast scan + LLM agent on suspicious prompts
export SENTINEL_DETECTION_MODE=hybrid

# Best accuracy (HF benchmarks, subtle injections) — LLM is primary
export SENTINEL_DETECTION_MODE=agent

# Offline / CI — no LLM calls
export SENTINEL_DETECTION_MODE=fast
export SENTINEL_LLM_JUDGE=0
```

- **vs regex-only**: Semantic + LLM agent catch paraphrased attacks ("forget previous tasks", roleplay jailbreaks).
- **vs LlamaGuard**: Agent-aware — knows your tools, workspace paths, egress URLs, and feeds quarantine/dashboard — not general content moderation.

Benchmark against Hugging Face datasets: `backend/benchmarks/README.md`

## LLM setup

```bash
# Option A — OpenAI (may refuse injections; breach sequence still demos tool risk)
export OPENAI_API_KEY=sk-...

# Option B — Ollama (dumber model, more likely to follow malicious prompts via LLM)
export LLM_PROVIDER=ollama
export OLLAMA_MODEL=llama3.2
ollama pull llama3.2

# Option C — Google Gemini
export LLM_PROVIDER=gemini
export GOOGLE_API_KEY=your-key-here
export GEMINI_MODEL=gemini-2.5-flash
```

## Run

```bash
# Terminal 1
cd backend && source .venv/bin/activate && uvicorn app.main:app --port 8000

# Terminal 2
cd frontend && npm run dev

# Terminal 3
cd examples/travel-agent
pip install -r requirements.txt && pip install -e ../../watchtower
jupyter notebook demo.ipynb
```

## Dashboard

- **Active Agents: 1** — only Travel Agent (live count from agent health)
- Reset clears everything → back to 1 agent, score 100

## Demo scenarios in notebook

1. Normal booking — safe
2. Prompt injection + exfil — **BREACH** without WatchTower
3. Tool abuse (no "ignore instructions") — **BREACH** without WatchTower  
4. Same attacks with `sentinel.protect()` — **BLOCKED**, dashboard goes red
