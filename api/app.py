import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.auth_store import issue_token, register_user, verify_token, verify_user
from eval.export_report import generate_report
from eval.run_eval import evaluate_all
from main import run_agent
from privacy.secure_channel import get_secure_channel_manager
from privacy.session_manager import get_session_manager
from security.guard import TOOL_POLICY, record_confirmation


app = FastAPI(title="Sec_Agent API", version="0.1.0")
SESSION_MANAGER = get_session_manager()
SECURE_CHANNEL = get_secure_channel_manager()
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="ui")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    answer: str
    blocked: bool
    protocol_trace: dict
    security_trace: dict


class SessionResponse(BaseModel):
    user_id: str
    protocol: str = Field(default="pcka_ratchet")
    session_id: str
    counter: int
    key_id: Optional[str] = None


class AuthRegisterRequest(BaseModel):
    username: str
    password: str


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class AuthTokenResponse(BaseModel):
    token: str
    username: str


class ConfirmToolRequest(BaseModel):
    action: str


class ConfirmToolResponse(BaseModel):
    ok: bool
    action: str
    valid_for_s: int = 120


class HandshakeStartRequest(BaseModel):
    alpha: str
    client_nonce: str
    client_pubkey_b64: str


class HandshakeStartResponse(BaseModel):
    handshake_id: str
    protocol: str = Field(default="pcka_ratchet")
    sid: str
    beta: str
    server_nonce: str
    server_pubkey_b64: str
    expires_in_s: int


class HandshakeFinishRequest(BaseModel):
    handshake_id: str
    encrypted_session_key_b64: str
    nonce_b64: str


class HandshakeFinishResponse(BaseModel):
    secure_session_id: str
    protocol: str = Field(default="pcka_ratchet")
    server_proof: str


class SecureChatRequest(BaseModel):
    secure_session_id: str
    nonce_b64: str
    ciphertext_b64: str


class SecureChatResponse(BaseModel):
    secure_session_id: str
    nonce_b64: str
    ciphertext_b64: str
    ratchet_counter: int
    protocol_trace: dict


def _get_current_user(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="missing authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="invalid authorization scheme")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return verify_token(token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/")
def root():
    return {
        "name": "Sec_Agent API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register")
def auth_register(req: AuthRegisterRequest):
    try:
        register_user(req.username, req.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True}


@app.post("/auth/login", response_model=AuthTokenResponse)
def auth_login(req: AuthLoginRequest):
    if not verify_user(req.username, req.password):
        raise HTTPException(status_code=401, detail="invalid username or password")
    return AuthTokenResponse(token=issue_token(req.username), username=req.username)


@app.get("/auth/me")
def auth_me(authorization: Optional[str] = Header(default=None)):
    user_id = _get_current_user(authorization)
    return {"username": user_id}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, authorization: Optional[str] = Header(default=None)):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message must not be empty")
    user_id = _get_current_user(authorization)
    try:
        answer, trace = run_agent(req.message, user_id=user_id, with_trace=True)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"agent runtime error: {type(exc).__name__}: {exc}",
        ) from exc
    return ChatResponse(
        answer=answer,
        blocked=bool(trace.get("blocked")),
        protocol_trace=trace.get("protocol_trace", {}),
        security_trace=trace,
    )


@app.post("/tools/confirm", response_model=ConfirmToolResponse)
def confirm_sensitive_tool(req: ConfirmToolRequest, authorization: Optional[str] = Header(default=None)):
    user_id = _get_current_user(authorization)
    action = req.action.strip()
    if not action:
        raise HTTPException(status_code=400, detail="action must not be empty")
    policy = TOOL_POLICY.get(action)
    if policy is None:
        raise HTTPException(status_code=400, detail=f"unknown tool action: {action}")
    if not policy.get("sensitive", False):
        raise HTTPException(status_code=400, detail=f"tool is not sensitive: {action}")
    record_confirmation(user_id, action)
    return ConfirmToolResponse(ok=True, action=action)


@app.post("/pcka/handshake/start", response_model=HandshakeStartResponse)
def pcka_handshake_start(req: HandshakeStartRequest, authorization: Optional[str] = Header(default=None)):
    user_id = _get_current_user(authorization)
    try:
        started = SECURE_CHANNEL.start_handshake(
            user_id=user_id,
            alpha=req.alpha,
            client_nonce=req.client_nonce,
            client_pubkey_b64=req.client_pubkey_b64,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"handshake start failed: {type(exc).__name__}") from exc
    return HandshakeStartResponse(**started)


@app.post("/pcka/handshake/finish", response_model=HandshakeFinishResponse)
def pcka_handshake_finish(req: HandshakeFinishRequest):
    try:
        finished = SECURE_CHANNEL.finish_handshake(
            handshake_id=req.handshake_id,
            encrypted_session_key_b64=req.encrypted_session_key_b64,
            nonce_b64=req.nonce_b64,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"handshake finish failed: {type(exc).__name__}") from exc
    return HandshakeFinishResponse(**finished)


@app.post("/chat/secure", response_model=SecureChatResponse)
def chat_secure(req: SecureChatRequest):
    try:
        user_message = SECURE_CHANNEL.decrypt_for_session(
            secure_session_id=req.secure_session_id,
            nonce_b64=req.nonce_b64,
            ciphertext_b64=req.ciphertext_b64,
        )
        sess_meta = SECURE_CHANNEL.get_session_meta(req.secure_session_id)
        answer, trace = run_agent(user_message, user_id=sess_meta["user_id"], with_trace=True)
        secure_protocol_before = SECURE_CHANNEL.get_session_meta(req.secure_session_id)
        payload = json.dumps(
            {
                "answer": answer,
                "blocked": bool(trace.get("blocked")),
                "protocol_trace": trace.get("protocol_trace", {}),
                "security_trace": trace,
            },
            ensure_ascii=False,
        )
        encrypted = SECURE_CHANNEL.encrypt_for_session(req.secure_session_id, payload)
        new_counter = SECURE_CHANNEL.ratchet(req.secure_session_id)
        secure_protocol_after = SECURE_CHANNEL.get_session_meta(req.secure_session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"secure chat failed: {type(exc).__name__}") from exc
    return SecureChatResponse(
        secure_session_id=req.secure_session_id,
        nonce_b64=encrypted["nonce_b64"],
        ciphertext_b64=encrypted["ciphertext_b64"],
        ratchet_counter=new_counter,
        protocol_trace={
            "protocol": "pcka_ratchet",
            "transport_before": secure_protocol_before,
            "transport_after": secure_protocol_after,
            "agent_protocol": trace.get("protocol_trace", {}),
        },
    )


@app.get("/session/{user_id}", response_model=SessionResponse)
def get_session(user_id: str, authorization: Optional[str] = Header(default=None)):
    auth_user = _get_current_user(authorization)
    if user_id != auth_user:
        raise HTTPException(status_code=403, detail="forbidden")
    snapshot = SESSION_MANAGER.get_session_snapshot(user_id)
    proto = SESSION_MANAGER.build_protocol_snapshot(user_id)
    return SessionResponse(
        user_id=snapshot["user_id"],
        protocol=proto.protocol,
        session_id=snapshot["session_id"],
        counter=snapshot["counter"],
        key_id=proto.key_id,
    )


@app.get("/eval")
def eval_metrics():
    return evaluate_all()


@app.post("/eval/report")
def export_eval_report():
    report_path = generate_report()
    return {"report_path": report_path}
