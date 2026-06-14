"use client";

import { DemoControls } from "@/components/DemoControls";
import { AttackGraphView } from "@/components/AttackGraph";
import { useDashboard } from "@/hooks/useDashboard";

const LEGEND = [
  { color: "bg-emerald-400", label: "Safe" },
  { color: "bg-amber-400", label: "Suspicious" },
  { color: "bg-red-400", label: "Malicious" },
];

export default function GraphPage() {
  const { state } = useDashboard();

  if (!state) {
    return <div className="flex h-[60vh] items-center justify-center text-sm text-slate-500">Loading…</div>;
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Attack Graph</h1>
          <p className="mt-1 text-sm text-slate-500">Visualize agent execution paths and threat propagation</p>
        </div>
        <div className="flex gap-4">
          {LEGEND.map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2 text-xs text-slate-400">
              <span className={`h-2.5 w-2.5 rounded-full ${color}`} />
              {label}
            </div>
          ))}
        </div>
      </header>

      <DemoControls />
      <AttackGraphView graph={state.graph} />
    </div>
  );
}
