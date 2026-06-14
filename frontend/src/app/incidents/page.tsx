"use client";

import { DemoControls } from "@/components/DemoControls";
import { IncidentReport } from "@/components/SecurityPanels";
import { useDashboard } from "@/hooks/useDashboard";

export default function IncidentsPage() {
  const { state } = useDashboard();

  if (!state) {
    return <div className="flex h-[60vh] items-center justify-center text-sm text-slate-500">Loading…</div>;
  }

  const incident = state.incidents[0] ?? null;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-white">Incident Report</h1>
        <p className="mt-1 text-sm text-slate-500">Auto-generated security incident documentation</p>
      </header>

      <DemoControls />
      <IncidentReport incident={incident} />
    </div>
  );
}
