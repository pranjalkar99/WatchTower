"use client";

import { scoreColor, statusBg, statusColor, statusDot, agentLabel } from "@/lib/utils";
import type { Agent, DashboardStats, SecurityEvent } from "@/lib/types";

export function StatCards({ stats, agents }: { stats: DashboardStats; agents?: { status: string }[] }) {
  const liveActive = agents
    ? agents.filter((a) => a.status === "healthy").length
    : stats.active_agents;
  const cards = [
    { label: "Active Agents", value: liveActive, suffix: "" },
    { label: "Security Score", value: stats.security_score, suffix: "/100", color: scoreColor(stats.security_score) },
    { label: "Incidents Today", value: stats.incidents_today, suffix: "", alert: stats.incidents_today > 0 },
    { label: "Blocked Attacks", value: stats.blocked_attacks, suffix: "" },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {cards.map((c) => (
        <div
          key={c.label}
          className={`glass rounded-xl p-4 ${c.alert ? "stat-glow-red border-red-500/20" : "stat-glow-green"}`}
        >
          <div className="text-xs font-medium uppercase tracking-wider text-slate-500">{c.label}</div>
          <div className={`mt-1 text-3xl font-bold tabular-nums ${c.color ?? "text-white"}`}>
            {c.value}
            {c.suffix && <span className="text-lg text-slate-500">{c.suffix}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

export function AgentCards({ agents }: { agents: Agent[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {agents.map((agent) => (
        <div key={agent.id} className={`glass rounded-xl border p-4 ${statusBg(agent.status)}`}>
          <div className="flex items-center gap-2">
            <span className={statusDot(agent.status)} />
            <span className="font-medium text-white">{agent.name}</span>
          </div>
          <div className={`mt-2 text-sm font-semibold uppercase tracking-wide ${statusColor(agent.status)}`}>
            {agentLabel(agent.status)}
          </div>
          <div className="mt-1 text-xs text-slate-500">{agent.description}</div>
        </div>
      ))}
    </div>
  );
}

export function EventFeed({ events }: { events: SecurityEvent[] }) {
  const sorted = [...events].reverse();

  return (
    <div className="glass flex h-full flex-col rounded-xl">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Live Event Feed</h3>
        <span className="live-dot h-2 w-2 rounded-full bg-red-400" />
      </div>
      <div className="flex-1 space-y-0 overflow-y-auto p-2" style={{ maxHeight: 360 }}>
        {sorted.map((ev) => (
          <div
            key={ev.id}
            className={`event-enter flex gap-3 rounded-lg px-3 py-2.5 hover:bg-slate-800/40 ${
              ev.severity === "critical" ? "border-l-2 border-red-500 bg-red-500/5" : ""
            }`}
          >
            <span className="shrink-0 font-mono text-xs text-slate-500">{ev.timestamp}</span>
            <div className="min-w-0">
              <div className={`text-sm font-medium ${ev.severity === "critical" ? "text-red-300" : "text-slate-200"}`}>
                {ev.title}
              </div>
              {ev.detail && <div className="truncate text-xs text-slate-500">{ev.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
