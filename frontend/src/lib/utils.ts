import type { AgentStatus } from "@/lib/types";
import { clsx } from "clsx";

export function statusColor(status: AgentStatus | string) {
  switch (status) {
    case "healthy":
    case "safe":
    case "allowed":
      return "text-emerald-400";
    case "warning":
    case "suspicious":
      return "text-amber-400";
    case "quarantined":
    case "malicious":
    case "blocked":
    case "critical":
      return "text-red-400";
    default:
      return "text-slate-400";
  }
}

export function statusBg(status: AgentStatus | string) {
  switch (status) {
    case "healthy":
    case "safe":
    case "allowed":
      return "bg-emerald-500/10 border-emerald-500/30";
    case "warning":
    case "suspicious":
      return "bg-amber-500/10 border-amber-500/30";
    case "quarantined":
    case "malicious":
    case "blocked":
    case "critical":
      return "bg-red-500/10 border-red-500/30";
    default:
      return "bg-slate-800/50 border-slate-700";
  }
}

export function statusDot(status: AgentStatus | string) {
  return clsx("inline-block h-2.5 w-2.5 rounded-full", {
    "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]": status === "healthy" || status === "safe",
    "bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.6)]": status === "warning" || status === "suspicious",
    "bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.6)]":
      status === "quarantined" || status === "malicious" || status === "blocked",
  });
}

export function agentLabel(status: AgentStatus) {
  switch (status) {
    case "healthy":
      return "Healthy";
    case "warning":
      return "Warning";
    case "quarantined":
      return "Quarantined";
  }
}

export function scoreColor(score: number) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}
