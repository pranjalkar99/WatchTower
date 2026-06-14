import type { DashboardState } from "./types";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/events";

export async function fetchDashboard(): Promise<DashboardState> {
  const res = await fetch(`${API_BASE}/api/dashboard`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch dashboard");
  return res.json();
}

export async function triggerDemoPhase(phase: number) {
  const res = await fetch(`${API_BASE}/api/demo/phase/${phase}`, { method: "POST" });
  return res.json();
}

export async function restoreAgent() {
  const res = await fetch(`${API_BASE}/api/demo/restore`, { method: "POST" });
  return res.json();
}

export async function resetDemo() {
  const res = await fetch(`${API_BASE}/api/demo/reset`, { method: "POST" });
  return res.json();
}

export async function sendChatMessage(message: string, agentId = "travel", mode: "simulated" | "langgraph" = "simulated") {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, agent_id: agentId, mode }),
  });
  return res.json();
}

export async function fetchIntegrationInfo() {
  const res = await fetch(`${API_BASE}/api/integration`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch integration info");
  return res.json();
}

export async function fetchChatMessages() {
  const res = await fetch(`${API_BASE}/api/chat/messages`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch chat");
  return res.json();
}
