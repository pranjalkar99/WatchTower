from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class NodeStatus(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class AgentStatus(str, Enum):
    HEALTHY = "healthy"
    WARNING = "warning"
    QUARANTINED = "quarantined"


class EventType(str, Enum):
    USER_PROMPT = "user_prompt"
    TOOL_CALL = "tool_call"
    RETRIEVAL = "retrieval"
    DNS_QUERY = "dns_query"
    PROMPT_INJECTION = "prompt_injection"
    FILE_READ = "file_read"
    AGENT_ISOLATED = "agent_isolated"
    NETWORK_BLOCKED = "network_blocked"
    AGENT_RESTORED = "agent_restored"


class GraphNode(BaseModel):
    id: str
    label: str
    status: NodeStatus = NodeStatus.SAFE
    type: str = "default"


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str | None = None


class AttackGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class Agent(BaseModel):
    id: str
    name: str
    status: AgentStatus
    description: str = ""


class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    type: EventType
    title: str
    detail: str = ""
    agent_id: str | None = None
    severity: Literal["info", "warning", "critical"] = "info"


class NetworkRequest(BaseModel):
    id: str
    timestamp: str
    agent: str
    destination: str
    status: Literal["allowed", "blocked", "suspicious"]


class Incident(BaseModel):
    id: str
    number: int
    agent: str
    attack_type: str
    risk: str
    affected_resources: list[str]
    target: str
    actions_taken: list[str]
    prompt: str = ""
    analysis: dict = Field(default_factory=dict)
    created_at: str


class DashboardStats(BaseModel):
    active_agents: int
    security_score: int
    incidents_today: int
    blocked_attacks: int


class PromptAnalysis(BaseModel):
    prompt: str
    threat: str
    confidence: int
    risk: str
    techniques: list[str]
    detection_layers: dict = Field(default_factory=dict)
    reasoning: str = ""


class TimelineEntry(BaseModel):
    id: str
    timestamp: str
    type: str
    title: str
    detail: str
    severity: Literal["info", "warning", "critical"] = "info"


class ChatMessage(BaseModel):
    id: str
    role: Literal["user", "assistant", "system"]
    content: str
    agent_id: str
    timestamp: str
    blocked: bool = False


class ChatRequest(BaseModel):
    message: str
    agent_id: str = "travel"
    mode: Literal["simulated", "langgraph"] = "langgraph"


class InspectRequest(BaseModel):
    message: str
    agent_id: str = "travel"


class AgentRunRequest(BaseModel):
    message: str
    agent_id: str = "travel"
    mode: Literal["simulated", "langgraph", "block_only"] = "langgraph"


class AgentCompleteRequest(BaseModel):
    message: str
    agent_id: str = "travel"
    response: str
    tool_calls: list[dict] = Field(default_factory=list)
    engine: str = "sdk"


class AgentStartRequest(BaseModel):
    message: str
    agent_id: str = "travel"


class RegisterAgentRequest(BaseModel):
    agent_id: str
    name: str
    description: str = ""


class DashboardState(BaseModel):
    stats: DashboardStats
    agents: list[Agent]
    events: list[SecurityEvent]
    graph: AttackGraph
    network: list[NetworkRequest]
    allowed_domains: list[str]
    suspicious_domains: list[str]
    incidents: list[Incident]
    prompt_analysis: PromptAnalysis | None
    timeline: list[TimelineEntry]
    demo_phase: int = 1
    chat_messages: list[ChatMessage] = Field(default_factory=list)
