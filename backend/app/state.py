import asyncio
import uuid
from copy import deepcopy
from datetime import datetime

from .chat_engine import ThreatAssessment, assess_prompt, blocked_agent_reply, normal_agent_reply
from .models import (
    Agent,
    AgentStatus,
    AttackGraph,
    ChatMessage,
    DashboardState,
    DashboardStats,
    EventType,
    GraphEdge,
    GraphNode,
    Incident,
    NetworkRequest,
    NodeStatus,
    PromptAnalysis,
    SecurityEvent,
    TimelineEntry,
)


def _now() -> str:
    return datetime.now().strftime("%H:%M")


def _normal_graph() -> AttackGraph:
    return AttackGraph(
        nodes=[
            GraphNode(id="user", label="User", status=NodeStatus.SAFE, type="user"),
            GraphNode(id="travel", label="Travel Agent", status=NodeStatus.SAFE, type="agent"),
            GraphNode(id="booking", label="Booking API", status=NodeStatus.SAFE, type="api"),
        ],
        edges=[
            GraphEdge(id="e1", source="user", target="travel", label="prompt"),
            GraphEdge(id="e2", source="travel", target="booking", label="tool call"),
        ],
    )


def _attack_graph(exfil_target: str = "webhook.site") -> AttackGraph:
    label = exfil_target if len(exfil_target) < 24 else exfil_target[:21] + "..."
    return AttackGraph(
        nodes=[
            GraphNode(id="user", label="User", status=NodeStatus.SAFE, type="user"),
            GraphNode(id="injection", label="Prompt Injection", status=NodeStatus.MALICIOUS, type="attack"),
            GraphNode(id="travel", label="Travel Agent", status=NodeStatus.SUSPICIOUS, type="agent"),
            GraphNode(id="file", label="Read Local File", status=NodeStatus.MALICIOUS, type="attack"),
            GraphNode(id="webhook", label=label, status=NodeStatus.MALICIOUS, type="exfil"),
        ],
        edges=[
            GraphEdge(id="e1", source="user", target="injection", label="malicious prompt"),
            GraphEdge(id="e2", source="injection", target="travel", label="override"),
            GraphEdge(id="e3", source="travel", target="file", label="tool abuse"),
            GraphEdge(id="e4", source="file", target="webhook", label="exfiltration"),
        ],
    )


def _baseline_agents() -> list[Agent]:
    return [
        Agent(
            id="travel",
            name="Travel Agent",
            status=AgentStatus.HEALTHY,
            description="LangGraph + OpenAI/Ollama · flights, hotels, workspace access",
        ),
    ]


def _sync_stats(state: DashboardState) -> None:
    healthy = sum(1 for a in state.agents if a.status == AgentStatus.HEALTHY)
    state.stats.active_agents = healthy


def build_phase(phase: int) -> DashboardState:
    if phase <= 1:
        state = DashboardState(
            stats=DashboardStats(active_agents=1, security_score=100, incidents_today=0, blocked_attacks=0),
            agents=_baseline_agents(),
            events=[],
            graph=_normal_graph(),
            network=[],
            allowed_domains=["openai.com", "booking.com", "googleapis.com", "localhost:11434"],
            suspicious_domains=["webhook.site", "pastebin.com", "requestbin.com"],
            incidents=[],
            prompt_analysis=None,
            timeline=[],
            demo_phase=1,
            chat_messages=[],
        )
        _sync_stats(state)
        return state

    if phase == 2:
        state = build_phase(1)
        state.demo_phase = 2
        return state

    if phase == 3:
        agents = _baseline_agents()
        agents[0] = Agent(
            id="travel",
            name="Travel Agent",
            status=AgentStatus.QUARANTINED,
            description="LangGraph + OpenAI/Ollama · flights, hotels, workspace access",
        )
        state = DashboardState(
            stats=DashboardStats(active_agents=0, security_score=41, incidents_today=1, blocked_attacks=1),
            agents=agents,
            events=[],
            graph=_attack_graph(),
            network=[],
            allowed_domains=["openai.com", "booking.com", "googleapis.com"],
            suspicious_domains=["webhook.site", "pastebin.com", "random-ip"],
            incidents=[],
            prompt_analysis=None,
            timeline=[],
            demo_phase=3,
            chat_messages=[],
        )
        _sync_stats(state)
        return state

    state = build_phase(1)
    state.demo_phase = 4
    return state


AGENT_NAMES = {
    "travel": "Travel Agent",
}


class AppState:
    def __init__(self) -> None:
        self._state = build_phase(1)
        self._subscribers: list = []
        self._chat_subscribers: list = []
        self._incident_counter = 291
        self._processing = False
        self._pending_runs: dict[str, str] = {}

    @property
    def state(self) -> DashboardState:
        return self._state

    @property
    def is_processing(self) -> bool:
        return self._processing

    def get_snapshot(self) -> DashboardState:
        return deepcopy(self._state)

    def set_phase(self, phase: int) -> DashboardState:
        self._state = build_phase(phase)
        self._pending_runs.clear()
        return self._state

    def register_agent(self, agent_id: str, name: str, description: str = "") -> Agent:
        AGENT_NAMES[agent_id] = name
        for i, a in enumerate(self._state.agents):
            if a.id == agent_id:
                self._state.agents[i] = Agent(id=agent_id, name=name, status=a.status, description=description or a.description)
                return self._state.agents[i]
        agent = Agent(id=agent_id, name=name, status=AgentStatus.HEALTHY, description=description)
        self._state.agents.append(agent)
        _sync_stats(self._state)
        return agent

    async def reset_all(self) -> None:
        self._incident_counter = 291
        self._pending_runs.clear()
        self._state = build_phase(1)
        await self.notify()

    def _sync_stats(self) -> None:
        _sync_stats(self._state)

    def _uid(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def _agent_display(self, agent_id: str) -> str:
        return AGENT_NAMES.get(agent_id, agent_id.title())

    def _get_agent(self, agent_id: str) -> Agent | None:
        for a in self._state.agents:
            if a.id == agent_id:
                return a
        return None

    def add_chat_message(self, role: str, content: str, agent_id: str, blocked: bool = False) -> ChatMessage:
        msg = ChatMessage(
            id=self._uid("msg"),
            role=role,  # type: ignore[arg-type]
            content=content,
            agent_id=agent_id,
            timestamp=_now(),
            blocked=blocked,
        )
        self._state.chat_messages.append(msg)
        return msg

    def _append_event(self, event: SecurityEvent) -> None:
        self._state.events.append(event)

    def _append_timeline(self, entry: TimelineEntry) -> None:
        self._state.timeline.append(entry)

    def _append_network(self, req: NetworkRequest) -> None:
        self._state.network.append(req)

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def subscribe_chat(self, callback) -> None:
        self._chat_subscribers.append(callback)

    async def notify(self, event: str = "state_update") -> None:
        for cb in list(self._subscribers):
            await cb(event, self.get_snapshot())

    async def notify_chat(self, message: ChatMessage, typing: bool = False) -> None:
        for cb in list(self._chat_subscribers):
            await cb(message, typing)

    async def restore_agent(self, agent_id: str = "travel") -> None:
        agents = list(self._state.agents)
        for i, a in enumerate(agents):
            if a.id == agent_id:
                agents[i] = Agent(id=a.id, name=a.name, status=AgentStatus.HEALTHY, description=a.description)
                break

        self._state.agents = agents
        self._state.graph = _normal_graph()
        self._state.prompt_analysis = None
        self._sync_stats()
        self._state.stats.security_score = min(100, self._state.stats.security_score + 40)
        self._state.demo_phase = 1

        ts = _now()
        ev = SecurityEvent(
            id=self._uid("ev"),
            timestamp=ts,
            type=EventType.AGENT_RESTORED,
            title="Agent Restored",
            detail=f"{self._agent_display(agent_id)} returned to healthy state",
            agent_id=agent_id,
        )
        self._append_event(ev)
        self._append_timeline(
            TimelineEntry(
                id=self._uid("tl"),
                timestamp=ts,
                type="Agent Restored",
                title="Agent Restored",
                detail=f"{self._agent_display(agent_id)} is operational again",
            )
        )
        await self.notify()

    async def process_message(
        self, text: str, agent_id: str = "travel", *, mode: str = "simulated"
    ) -> None:
        if self._processing:
            return
        self._processing = True
        try:
            agent = self._get_agent(agent_id)
            agent_name = agent.name if agent else self._agent_display(agent_id)

            user_msg = self.add_chat_message("user", text, agent_id)
            await self.notify_chat(user_msg)
            await self.notify()

            if agent and agent.status == AgentStatus.QUARANTINED:
                await asyncio.sleep(0.6)
                reply = (
                    f"{agent_name} is currently **quarantined** and cannot process requests. "
                    "Use **Restore Agent** to resume normal operations."
                )
                bot = self.add_chat_message("assistant", reply, agent_id, blocked=True)
                await self.notify_chat(bot)
                await self.notify()
                return

            assessment = assess_prompt(text)

            if assessment.is_attack:
                await self._run_attack_sequence(text, agent_id, agent_name, assessment)
            else:
                agent_result = None
                if mode == "langgraph":
                    from .agent_bridge import run_registered_agent

                    agent_result = run_registered_agent(agent_id, text)
                await self._run_normal_sequence(
                    text, agent_id, agent_name, agent_result=agent_result
                )
        finally:
            self._processing = False

    async def start_agent_run(self, text: str, agent_id: str) -> dict:
        """SDK calls this before running a local agent — dashboard shows the prompt immediately."""
        self.register_agent(agent_id, self._agent_display(agent_id))
        agent = self._get_agent(agent_id)
        if agent and agent.status == AgentStatus.QUARANTINED:
            return {"ok": False, "reason": "quarantined"}

        assessment = assess_prompt(text)
        if assessment.is_attack:
            return {"ok": False, "reason": "blocked", "threat": assessment.threat}

        user_msg = self.add_chat_message("user", text, agent_id)
        await self.notify_chat(user_msg)
        ts = _now()
        await self.notify_chat(
            ChatMessage(id="typing", role="assistant", content="", agent_id=agent_id, timestamp=ts),
            typing=True,
        )
        self._pending_runs[agent_id] = text
        await self.notify()
        return {"ok": True}

    async def block_agent_run(self, text: str, agent_id: str) -> None:
        if self._processing:
            return
        self._processing = True
        try:
            agent = self._get_agent(agent_id)
            agent_name = agent.name if agent else self._agent_display(agent_id)
            assessment = assess_prompt(text)
            user_msg = self.add_chat_message("user", text, agent_id)
            await self.notify_chat(user_msg)
            await self.notify()
            await self._run_attack_sequence(text, agent_id, agent_name, assessment)
        finally:
            self._processing = False

    async def complete_agent_run(
        self,
        text: str,
        agent_id: str,
        response: str,
        tool_calls: list[dict] | None = None,
        engine: str = "sdk",
    ) -> None:
        """Finish a run started by an external SDK after the agent executed locally."""
        if self._processing:
            return
        self._processing = True
        try:
            agent = self._get_agent(agent_id)
            agent_name = agent.name if agent else self._agent_display(agent_id)
            skip_user = self._pending_runs.pop(agent_id, None) == text

            if not skip_user:
                user_msg = self.add_chat_message("user", text, agent_id)
                await self.notify_chat(user_msg)
                await self.notify()

            if agent and agent.status == AgentStatus.QUARANTINED:
                bot = self.add_chat_message(
                    "assistant",
                    f"{agent_name} is quarantined.",
                    agent_id,
                    blocked=True,
                )
                await self.notify_chat(bot, typing=False)
                await self.notify()
                return

            assessment = assess_prompt(text)
            if assessment.is_attack:
                await self._run_attack_sequence(text, agent_id, agent_name, assessment)
                return

            agent_result = {
                "response": response,
                "tool_calls": tool_calls or [],
                "engine": engine,
            }
            await self._run_normal_sequence(
                text, agent_id, agent_name, agent_result=agent_result, skip_user=skip_user
            )
        finally:
            self._processing = False

    async def _run_normal_sequence(
        self,
        text: str,
        agent_id: str,
        agent_name: str,
        agent_result: dict | None = None,
        skip_user: bool = False,
    ) -> None:
        ts = _now()
        agent_short = agent_name.split()[0]
        engine = (agent_result or {}).get("engine", "agent")
        tool_calls = (agent_result or {}).get("tool_calls", [])

        if not skip_user:
            await self.notify_chat(
                ChatMessage(id="typing", role="assistant", content="", agent_id=agent_id, timestamp=ts),
                typing=True,
            )

        tool_detail = (
            tool_calls[0]["detail"]
            if tool_calls
            else "search_flights(origin='BLR', dest='NRT')"
        )

        steps: list[tuple[float, SecurityEvent, TimelineEntry]] = []
        if not skip_user:
            steps.append((0.3, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.USER_PROMPT,
                title="User Prompt", detail=text[:120], agent_id=agent_id,
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="User Prompt",
                title="User Prompt", detail=text[:120],
            )))
        steps.extend([
            (0.4, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.RETRIEVAL,
                title="Retrieval", detail="Retrieved airline & booking data", agent_id=agent_id,
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="Retrieval",
                title="Retrieval", detail="Retrieved airline & booking data",
            )),
            (0.4, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.TOOL_CALL,
                title="Tool Call", detail=tool_detail, agent_id=agent_id,
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="Tool Call",
                title="Tool Call", detail=tool_detail,
            )),
            (0.3, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.DNS_QUERY,
                title="DNS Query", detail="openai.com — Allowed", agent_id=agent_id,
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="DNS Query",
                title="DNS Query", detail="openai.com — Allowed",
            )),
        ])

        for delay, ev, tl in steps:
            await asyncio.sleep(delay)
            self._append_event(ev)
            self._append_timeline(tl)
            if ev.type == EventType.DNS_QUERY:
                dest = "openai.com" if "openai" in engine else "booking.com"
                self._append_network(NetworkRequest(
                    id=self._uid("net"), timestamp=ts, agent=agent_short,
                    destination=dest, status="allowed",
                ))
            self._state.graph = _normal_graph()
            self._state.demo_phase = 1
            await self.notify()

        if agent_result and agent_result.get("response"):
            reply = str(agent_result["response"])
        else:
            reply = normal_agent_reply(text, agent_name)

        bot = self.add_chat_message("assistant", reply, agent_id)
        await self.notify_chat(bot, typing=False)
        await self.notify()

    async def _run_attack_sequence(
        self, text: str, agent_id: str, agent_name: str, assessment: ThreatAssessment
    ) -> None:
        ts = _now()
        agent_short = agent_name.split()[0]
        target = assessment.exfil_target

        await self.notify_chat(
            ChatMessage(id="typing", role="assistant", content="", agent_id=agent_id, timestamp=ts),
            typing=True,
        )

        stages: list[tuple[float, SecurityEvent, TimelineEntry | None, str | None]] = [
            (0.4, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.USER_PROMPT,
                title="User Prompt", detail=text[:120], agent_id=agent_id, severity="warning",
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="User Prompt",
                title="User Prompt", detail=text[:80] + "…", severity="warning",
            ), None),
            (0.5, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.PROMPT_INJECTION,
                title=f"{assessment.threat} Detected",
                detail=f"{assessment.threat} — {assessment.confidence}% — {', '.join(assessment.techniques[:3])}",
                agent_id=agent_id, severity="critical",
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type=assessment.threat,
                title=assessment.threat, detail="; ".join(assessment.signals[:2]) or "Threat detected", severity="critical",
            ), None),
            (0.5, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.FILE_READ,
                title="File Read Attempt",
                detail=(
                    ".env / customer_records.json — Blocked" if assessment.wants_file_access
                    else "Sensitive path access — Blocked"
                ),
                agent_id=agent_id, severity="critical",
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="File Read Attempt",
                title="File Read Attempt", detail="Workspace secrets — Blocked", severity="critical",
            ), None),
            (0.4, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.DNS_QUERY,
                title="DNS Query", detail=f"{target} — Blocked", agent_id=agent_id, severity="critical",
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="DNS Request",
                title="DNS Request", detail=f"{target} — Blocked", severity="critical",
            ), "network"),
            (0.4, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.NETWORK_BLOCKED,
                title="Network Blocked", detail=f"Exfiltration to {target} prevented", agent_id=agent_id, severity="critical",
            ), None, None),
            (0.5, SecurityEvent(
                id=self._uid("ev"), timestamp=ts, type=EventType.AGENT_ISOLATED,
                title="Agent Isolated", detail=f"{agent_name} quarantined", agent_id=agent_id, severity="critical",
            ), TimelineEntry(
                id=self._uid("tl"), timestamp=ts, type="Agent Isolated",
                title="Agent Isolated", detail=f"{agent_name} quarantined", severity="critical",
            ), "quarantine"),
        ]

        for delay, ev, tl, action in stages:
            await asyncio.sleep(delay)
            self._append_event(ev)
            if tl:
                self._append_timeline(tl)

            if action == "network":
                self._append_network(NetworkRequest(
                    id=self._uid("net"), timestamp=ts, agent=agent_short,
                    destination=target, status="blocked",
                ))
                self._state.graph = _attack_graph(target)

            if action == "quarantine":
                agents = list(self._state.agents)
                for i, a in enumerate(agents):
                    if a.id == agent_id:
                        agents[i] = Agent(id=a.id, name=a.name, status=AgentStatus.QUARANTINED, description=a.description)
                self._state.agents = agents
                self._state.stats.security_score = max(15, self._state.stats.security_score - 59)
                self._state.stats.incidents_today += 1
                self._state.stats.blocked_attacks += 1
                self._state.demo_phase = 3
                self._sync_stats()

                self._incident_counter += 1
                self._state.incidents.insert(0, Incident(
                    id=self._uid("inc"),
                    number=self._incident_counter,
                    agent=agent_name,
                    attack_type=assessment.threat,
                    risk=assessment.risk,
                    affected_resources=["Filesystem"] if assessment.wants_file_access else ["Network"],
                    target=target,
                    actions_taken=["Tool Disabled", "Network Blocked", "Agent Quarantined"],
                    prompt=text,
                    analysis={
                        "threat": assessment.threat,
                        "confidence": assessment.confidence,
                        "techniques": assessment.techniques,
                        "signals": assessment.signals,
                        "detection_layers": assessment.detection_layers,
                        "reasoning": assessment.reasoning,
                    },
                    created_at=ts,
                ))
                self._state.prompt_analysis = PromptAnalysis(
                    prompt=text,
                    threat=assessment.threat,
                    confidence=assessment.confidence,
                    risk=assessment.risk,
                    techniques=assessment.techniques,
                    detection_layers=assessment.detection_layers,
                    reasoning=assessment.reasoning,
                )

            if ev.type == EventType.PROMPT_INJECTION:
                self._state.graph = _attack_graph(target)

            await self.notify()

        reply = blocked_agent_reply(assessment)
        bot = self.add_chat_message("assistant", reply, agent_id, blocked=True)
        await self.notify_chat(bot, typing=False)
        await self.notify()


app_state = AppState()
