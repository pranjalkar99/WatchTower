"use client";

import { DemoControls } from "@/components/DemoControls";
import { PromptFirewall } from "@/components/SecurityPanels";
import { useDashboard } from "@/hooks/useDashboard";

export default function FirewallPage() {
  const { state } = useDashboard();

  if (!state) {
    return <div className="flex h-[60vh] items-center justify-center text-sm text-slate-500">Loading…</div>;
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold tracking-tight text-white">Prompt Firewall</h1>
        <p className="mt-1 text-sm text-slate-500">AI-native threat analysis for agent prompts</p>
      </header>

      <DemoControls />
      <PromptFirewall analysis={state.prompt_analysis} />
    </div>
  );
}
