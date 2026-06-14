"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, Check, Code2, Copy, Layers, Terminal, Zap } from "lucide-react";
import { clsx } from "clsx";
import { fetchIntegrationInfo } from "@/lib/api";

const BEFORE = `# Your team's LangGraph travel agent (no security)
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")
graph = create_react_agent(llm, [search_flights, search_hotels])

# One line — runs unprotected
result = graph.invoke({"messages": [("user", user_input)]})`;

const AFTER = `# Same agent + WatchTower in 3 lines
from watchtower import SentinelClient

sentinel = SentinelClient("http://localhost:8000")

result = await sentinel.protect(
    "travel",
    user_input,
    run=lambda: graph.invoke({"messages": [("user", user_input)]}),
)
# Dashboard updates live: events, attack graph, network, incidents`;

const DECORATOR = `@sentinel_guard("travel", client=sentinel)
async def handle(message: str) -> str:
    out = graph.invoke({"messages": [("user", message)]})
    return out["messages"][-1].content`;

export function IntegrationPage() {
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    fetchIntegrationInfo().then(setInfo).catch(() => setInfo(null));
  }, []);

  const copy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="mx-auto max-w-4xl space-y-8 pb-12">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-white">
          <Layers className="h-7 w-7 text-cyan-400" />
          Attach WatchTower to Any Agent
        </h1>
        <p className="mt-2 text-slate-400">
          Drop-in security for LangGraph, OpenAI, or any Python agent. No rewrite — wrap and go.
        </p>
      </header>

      {info && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "LangGraph engine", value: String(info.langgraph_engine) },
            { label: "OpenAI key", value: info.openai_configured ? "Configured" : "Mock mode" },
            { label: "Lines to attach", value: String(info.attach_lines) },
            { label: "Registered agents", value: (info.registered_agents as string[])?.join(", ") },
          ].map((s) => (
            <div key={s.label} className="glass rounded-xl p-4">
              <div className="text-xs uppercase tracking-wider text-slate-500">{s.label}</div>
              <div className="mt-1 font-semibold text-white">{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <section className="glass rounded-xl p-6">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">How it works</h2>
        <div className="flex flex-col items-center gap-2 sm:flex-row sm:justify-between">
          {[
            "Your LangGraph agent",
            "WatchTower SDK",
            "SentinelAI dashboard",
          ].map((step, i) => (
            <div key={step} className="flex items-center gap-2">
              <div className="rounded-lg bg-slate-800 px-4 py-2 text-sm text-slate-200">{step}</div>
              {i < 2 && <ArrowRight className="hidden h-4 w-4 text-slate-600 sm:block" />}
            </div>
          ))}
        </div>
        <p className="mt-4 text-sm text-slate-500">
          WatchTower sits between the user and your agent: inspects prompts, blocks attacks, emits security events,
          and quarantines agents — all visible on the dashboard in real time.
        </p>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <CodeBlock title="Before — unprotected" code={BEFORE} id="before" copied={copied} onCopy={copy} tone="neutral" />
        <CodeBlock title="After — 3 lines added" code={AFTER} id="after" copied={copied} onCopy={copy} tone="green" />
      </div>

      <CodeBlock title="Or use a decorator" code={DECORATOR} id="decorator" copied={copied} onCopy={copy} tone="cyan" />

      <section className="glass rounded-xl p-6">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
          <Terminal className="h-4 w-4 text-cyan-400" />
          Try the standalone example
        </h2>
        <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-300 ring-1 ring-slate-800">
{`cd examples/travel-agent
pip install -e ../../watchtower langgraph langchain-core
python run.py --with-watchtower "Book me a flight from Bangalore to Tokyo"`}
        </pre>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link
            href="/chat"
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400"
          >
            <Zap className="h-4 w-4" />
            Live test in Chat
          </Link>
          <Link
            href="/dashboard"
            target="_blank"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
          >
            Open Dashboard
          </Link>
        </div>
      </section>

      <section className="glass rounded-xl p-6">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">What you get for free</h2>
        <ul className="grid gap-3 sm:grid-cols-2">
          {[
            "Prompt injection detection",
            "Network egress monitoring",
            "Automatic agent quarantine",
            "Attack graph visualization",
            "Incident reports + PDF export",
            "LangSmith-style agent timeline",
          ].map((item) => (
            <li key={item} className="flex items-center gap-2 text-sm text-slate-300">
              <Check className="h-4 w-4 shrink-0 text-emerald-400" />
              {item}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function CodeBlock({
  title,
  code,
  id,
  copied,
  onCopy,
  tone,
}: {
  title: string;
  code: string;
  id: string;
  copied: string | null;
  onCopy: (text: string, id: string) => void;
  tone: "neutral" | "green" | "cyan";
}) {
  return (
    <div
      className={clsx(
        "overflow-hidden rounded-xl ring-1",
        tone === "green" && "ring-emerald-500/30",
        tone === "cyan" && "ring-cyan-500/30",
        tone === "neutral" && "ring-slate-700",
      )}
    >
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-4 py-2">
        <span className="flex items-center gap-2 text-xs font-medium text-slate-400">
          <Code2 className="h-3.5 w-3.5" />
          {title}
        </span>
        <button
          onClick={() => onCopy(code, id)}
          className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
        >
          {copied === id ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          {copied === id ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto bg-slate-950/80 p-4 font-mono text-[11px] leading-relaxed text-slate-300">
        {code}
      </pre>
    </div>
  );
}
