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

## LLM setup

```bash
# Option A — OpenAI (may refuse injections; breach sequence still demos tool risk)
export OPENAI_API_KEY=sk-...

# Option B — Ollama (dumber model, more likely to follow malicious prompts via LLM)
export LLM_PROVIDER=ollama
export OLLAMA_MODEL=llama3.2
ollama pull llama3.2
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
