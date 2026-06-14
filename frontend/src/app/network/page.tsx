"use client";

import { DemoControls } from "@/components/DemoControls";
import { DnsPanels, NetworkTable } from "@/components/NetworkPanel";
import { useDashboard } from "@/hooks/useDashboard";

export default function NetworkPage() {
  const { state } = useDashboard();

  if (!state) {
    return <div className="flex h-[60vh] items-center justify-center text-sm text-slate-500">Loading…</div>;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-white">Network Security</h1>
        <p className="mt-1 text-sm text-slate-500">Outbound request monitoring and DNS policy enforcement</p>
      </header>

      <DemoControls />
      <NetworkTable requests={state.network} />
      <DnsPanels allowed={state.allowed_domains} suspicious={state.suspicious_domains} />
    </div>
  );
}
