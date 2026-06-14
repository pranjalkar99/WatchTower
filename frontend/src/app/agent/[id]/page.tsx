"use client";

import { use } from "react";
import { DemoControls } from "@/components/DemoControls";
import { AgentTimeline } from "@/components/AgentTimeline";
import { useDashboard } from "@/hooks/useDashboard";

export default function AgentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { state } = useDashboard();

  if (!state) {
    return <div className="flex h-[60vh] items-center justify-center text-sm text-slate-500">Loading…</div>;
  }

  const agent = state.agents.find((a) => a.id === id);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-white">Agent Timeline</h1>
        <p className="mt-1 text-sm text-slate-500">
          {agent ? `${agent.name} — execution trace` : `Agent: ${id}`}
        </p>
      </header>

      <DemoControls />
      <AgentTimeline entries={state.timeline} />
    </div>
  );
}
