"use client";

import { Play, RotateCcw, ShieldCheck, Zap } from "lucide-react";
import { restoreAgent, resetDemo, triggerDemoPhase } from "@/lib/api";
import { useDashboard } from "@/hooks/useDashboard";

export function DemoControls() {
  const { state } = useDashboard();
  const phase = state?.demo_phase ?? 1;

  return (
    <div className="glass flex flex-wrap items-center gap-2 rounded-xl px-4 py-3">
      <span className="mr-2 text-xs font-medium uppercase tracking-wider text-slate-500">Demo</span>
      <button
        onClick={() => resetDemo()}
        className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 transition hover:bg-emerald-500/20"
      >
        <RotateCcw className="h-3.5 w-3.5" />
        Phase 1: Normal
      </button>
      <button
        onClick={() => triggerDemoPhase(2)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-500/20"
      >
        <Zap className="h-3.5 w-3.5" />
        Phase 2: Attack
      </button>
      <button
        onClick={() => restoreAgent()}
        className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 transition hover:bg-cyan-500/20"
      >
        <ShieldCheck className="h-3.5 w-3.5" />
        Restore Agent
      </button>
      <span className="ml-auto flex items-center gap-1.5 text-xs text-slate-500">
        <Play className="h-3 w-3" />
        Phase {phase}/4
      </span>
    </div>
  );
}
