import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .chat_engine import assess_prompt
from .models import (
    AgentCompleteRequest,
    AgentRunRequest,
    AgentStartRequest,
    ChatMessage,
    ChatRequest,
    DashboardState,
    InspectRequest,
    RegisterAgentRequest,
)
from .state import app_state


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(title="SentinelAI API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _serialize(state: DashboardState) -> dict:
    return json.loads(state.model_dump_json())


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/dashboard")
async def get_dashboard() -> dict:
    return _serialize(app_state.get_snapshot())


@app.get("/api/events")
async def get_events():
    state = app_state.get_snapshot()
    return {"events": [e.model_dump() for e in state.events]}


@app.get("/api/agents")
async def get_agents():
    state = app_state.get_snapshot()
    return {"agents": [a.model_dump() for a in state.agents]}


@app.get("/api/incidents")
async def get_incidents():
    state = app_state.get_snapshot()
    return {"incidents": [i.model_dump() for i in state.incidents]}


@app.get("/api/network")
async def get_network():
    state = app_state.get_snapshot()
    return {
        "requests": [r.model_dump() for r in state.network],
        "allowed_domains": state.allowed_domains,
        "suspicious_domains": state.suspicious_domains,
    }


@app.get("/api/graph")
async def get_graph():
    state = app_state.get_snapshot()
    return state.graph.model_dump()


@app.get("/api/timeline/{agent_id}")
async def get_timeline(agent_id: str):
    state = app_state.get_snapshot()
    return {"agent_id": agent_id, "timeline": [t.model_dump() for t in state.timeline]}


@app.get("/api/firewall")
async def get_firewall():
    state = app_state.get_snapshot()
    if state.prompt_analysis:
        return state.prompt_analysis.model_dump()
    return {"prompt": "", "threat": "None", "confidence": 0, "risk": "Low", "techniques": []}


@app.get("/api/chat/messages")
async def get_chat_messages():
    state = app_state.get_snapshot()
    return {"messages": [m.model_dump() for m in state.chat_messages]}


@app.post("/api/chat")
async def send_chat(request: ChatRequest):
    text = request.message.strip()
    if not text:
        return {"error": "Message cannot be empty"}

    if app_state.is_processing:
        return {"error": "Agent is still processing the previous message"}

    asyncio.create_task(
        app_state.process_message(text, request.agent_id, mode=request.mode)
    )
    return {"status": "processing", "agent_id": request.agent_id, "mode": request.mode}


@app.post("/api/sentinel/inspect")
async def inspect_prompt(request: InspectRequest):
    text = request.message.strip()
    if not text:
        return {"error": "Message cannot be empty"}
    assessment = assess_prompt(text)
    agent = app_state.state.agents
    quarantined = any(
        a.id == request.agent_id and a.status.value == "quarantined" for a in agent
    )
    return {
        "blocked": assessment.is_attack or quarantined,
        "threat": assessment.threat if assessment.is_attack else None,
        "confidence": assessment.confidence,
        "risk": assessment.risk,
        "techniques": assessment.techniques,
        "signals": assessment.signals,
        "category": assessment.category,
        "detection_layers": assessment.detection_layers,
        "reasoning": assessment.reasoning,
        "quarantined": quarantined,
    }


@app.post("/api/sentinel/inspect-tool")
async def inspect_tool(tool_name: str, args: dict):
    from .chat_engine import assess_tool_call
    a = assess_tool_call(tool_name, args)
    return {
        "blocked": a.is_attack,
        "threat": a.threat,
        "confidence": a.confidence,
        "techniques": a.techniques,
        "signals": a.signals,
    }


@app.get("/api/integration")
async def integration_info():
    from .agent_bridge import run_registered_agent

    try:
        probe = run_registered_agent("travel", "ping")
        engine = probe.get("engine", "unknown")
        langgraph_available = True
    except Exception as exc:
        engine = "simulated"
        langgraph_available = False
        probe = {"error": str(exc)}

    return {
        "sdk": "pip install -e ./watchtower",
        "attach_lines": 3,
        "registered_agents": ["travel"],
        "langgraph_engine": engine,
        "langgraph_available": langgraph_available,
        "openai_configured": bool(__import__("os").getenv("OPENAI_API_KEY")),
        "gemini_configured": bool(
            __import__("os").getenv("GOOGLE_API_KEY") or __import__("os").getenv("GEMINI_API_KEY")
        ),
        "snippet": (
            "from watchtower import SentinelClient\n"
            "sentinel = SentinelClient('http://localhost:8000')\n"
            "result = await sentinel.protect('travel', message, run=lambda: graph.invoke(...))"
        ),
    }


@app.post("/api/agent/run")
async def agent_run(request: AgentRunRequest):
    text = request.message.strip()
    if not text:
        return {"error": "Message cannot be empty"}
    if app_state.is_processing:
        return {"error": "Agent is still processing the previous message"}

    if request.mode == "block_only":
        asyncio.create_task(app_state.block_agent_run(text, request.agent_id))
        return {"status": "processing", "blocked": True}

    mode = "langgraph" if request.mode == "langgraph" else "simulated"
    asyncio.create_task(app_state.process_message(text, request.agent_id, mode=mode))
    return {"status": "processing", "agent_id": request.agent_id, "mode": mode}


@app.post("/api/agent/start")
async def agent_start(request: AgentStartRequest):
    text = request.message.strip()
    if not text:
        return {"error": "Message cannot be empty"}
    result = await app_state.start_agent_run(text, request.agent_id)
    return result


@app.post("/api/agent/complete")
async def agent_complete(request: AgentCompleteRequest):
    text = request.message.strip()
    if not text:
        return {"error": "Message cannot be empty"}
    if app_state.is_processing:
        return {"error": "Agent is still processing the previous message"}

    asyncio.create_task(
        app_state.complete_agent_run(
            text,
            request.agent_id,
            request.response,
            request.tool_calls,
            request.engine,
        )
    )
    return {"status": "processing", "agent_id": request.agent_id}


@app.post("/api/agents/register")
async def register_agent(request: RegisterAgentRequest):
    agent = app_state.register_agent(request.agent_id, request.name, request.description)
    await app_state.notify()
    return agent.model_dump()


@app.post("/api/demo/phase/{phase}")
async def set_demo_phase(phase: int):
    if phase not in (1, 2, 3, 4):
        return {"error": "Phase must be 1-4"}

    app_state.set_phase(phase)

    if phase == 2:
        await asyncio.sleep(0.3)
        app_state.set_phase(3)

    await app_state.notify("state_update")
    return {"phase": app_state.state.demo_phase, "message": f"Demo phase {phase} activated"}


@app.post("/api/demo/restore")
async def restore_agent():
    await app_state.restore_agent("travel")
    reply = app_state.add_chat_message(
        "system",
        "Travel Agent has been restored. Security posture improving.",
        "travel",
    )
    await _broadcast_chat(reply)
    return {"phase": 4, "message": "Agent restored"}


@app.post("/api/demo/reset")
async def reset_demo():
    await app_state.reset_all()
    await manager.broadcast({"type": "chat_clear"})
    return {"phase": 1, "message": "Dashboard reset — all agents healthy, events cleared"}


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.append(websocket)
        await websocket.send_json({"type": "state_update", "data": _serialize(app_state.get_snapshot())})
        messages = app_state.get_snapshot().chat_messages
        if messages:
            await websocket.send_json({
                "type": "chat_history",
                "data": [m.model_dump() for m in messages],
            })

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict) -> None:
        dead: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def _broadcast_chat(message: ChatMessage, typing: bool = False) -> None:
    await manager.broadcast({
        "type": "chat_typing" if typing else "chat_message",
        "data": message.model_dump(),
        "typing": typing,
    })


async def _on_state_update(_event: str, state: DashboardState) -> None:
    await manager.broadcast({"type": "state_update", "data": _serialize(state)})


async def _on_chat_update(message: ChatMessage, typing: bool = False) -> None:
    await _broadcast_chat(message, typing)


app_state.subscribe(_on_state_update)
app_state.subscribe_chat(_on_chat_update)


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
