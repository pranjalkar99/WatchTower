"use client";

import { DemoControls } from "@/components/DemoControls";
import { AgentCards, EventFeed, StatCards } from "@/components/DashboardWidgets";
import { AttackGraphView } from "@/components/AttackGraph";
import { useDashboard } from "@/hooks/useDashboard";

export default function DashboardPage() {
  const { state } = useDashboard();

  if (!state) {
    return (
      <div className="flex h-[60vh] items-center justify-center">
        <div className="text-sm text-slate-500">Loading SentinelAI…</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-white">Security Command Center</h1>
        <p className="mt-1 text-sm text-slate-500">Real-time AI agent security monitoring</p>
      </header>

      <DemoControls />
      <StatCards stats={state.stats} agents={state.agents} />

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Agent Health</h2>
        <AgentCards agents={state.agents} />
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Attack Graph</h2>
          <AttackGraphView graph={state.graph} />
        </section>
        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Live Events</h2>
          <EventFeed events={state.events} />
        </section>
      </div>
    </div>
  );
}
