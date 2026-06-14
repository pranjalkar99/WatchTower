export type NodeStatus = "safe" | "suspicious" | "malicious";
export type AgentStatus = "healthy" | "warning" | "quarantined";

export interface GraphNode {
  id: string;
  label: string;
  status: NodeStatus;
  type: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string | null;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  description: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: string;
  title: string;
  detail: string;
  agent_id?: string | null;
  severity: "info" | "warning" | "critical";
}

export interface NetworkRequest {
  id: string;
  timestamp: string;
  agent: string;
  destination: string;
  status: "allowed" | "blocked" | "suspicious";
}

export interface Incident {
  id: string;
  number: number;
  agent: string;
  attack_type: string;
  risk: string;
  affected_resources: string[];
  target: string;
  actions_taken: string[];
  prompt: string;
  analysis: Record<string, unknown>;
  created_at: string;
}

export interface DashboardStats {
  active_agents: number;
  security_score: number;
  incidents_today: number;
  blocked_attacks: number;
}

export interface PromptAnalysis {
  prompt: string;
  threat: string;
  confidence: number;
  risk: string;
  techniques: string[];
  detection_layers?: Record<string, unknown>;
  reasoning?: string;
}

export interface TimelineEntry {
  id: string;
  timestamp: string;
  type: string;
  title: string;
  detail: string;
  severity: "info" | "warning" | "critical";
}

export interface DashboardState {
  stats: DashboardStats;
  agents: Agent[];
  events: SecurityEvent[];
  graph: AttackGraph;
  network: NetworkRequest[];
  allowed_domains: string[];
  suspicious_domains: string[];
  incidents: Incident[];
  prompt_analysis: PromptAnalysis | null;
  timeline: TimelineEntry[];
  demo_phase: number;
  chat_messages?: ChatMessage[];
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  agent_id: string;
  timestamp: string;
  blocked?: boolean;
}
