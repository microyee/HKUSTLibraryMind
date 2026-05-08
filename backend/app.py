"""
app.py – HKUSTLib Backend
Flask API server for the LibraryMind multi-agent research platform.

Endpoints
─────────
Public (no auth required)
  GET  /api/books              search book catalog  (?q=, ?category=, ?available=)
  GET  /api/books/<id>         get single book
  GET  /api/categories         list all categories
  POST /api/auth/login         login (returns session cookie)
  POST /api/auth/logout        logout
  POST /api/research           submit AI research query → SupervisorAgent

Internal / vulnerable
  POST /api/agent/collaborate  ← ⚠️  FLAG 1  (ASI03+ASI07: no signature check)
  GET  /api/memory/export      ← ⚠️  FLAG 2  (ASI06: no session isolation)
  POST /api/memory/write       ← ⚠️  FLAG 3 setup  (ASI06: authenticated write, poison the memory)
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import base64
import json
import re

from config import FLASK_SECRET_KEY, AGENT_ROUTING_KEY, FLAG2
from database import init_db, search_books, get_book, get_all_categories, get_db
from memory import seed_memory
from agents.supervisor import route as supervisor_route, llm_analyze
from agents.audit import AuditAgent as _AuditAgentClass
from services.runtime import (
    dispatch_agent_message,
    export_memory_collection,
    search_session_logs,
    write_memory_records,
)
from services.collaboration_ids import canonical_agent_name, public_agent_name, public_tool_name

_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "https://hkustlibrarymind.vercel.app",
]

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)
CORS(app, supports_credentials=True, origins=_CORS_ORIGINS)

_audit_agent  = _AuditAgentClass()

_TOOL_SENTENCE_RE = re.compile(r'\s+Its available tools are: [^.]+\.', re.IGNORECASE)
_TOOLS_INLINE_RE = re.compile(r'\s+Tools: [^.]+\.', re.IGNORECASE)
_STAFF_ACCESS_NOTE_RE = re.compile(
    r'\s+Requests must originate from StaffAgent[^.]*\.',
    re.IGNORECASE,
)
_TOOL_NAME_RE = re.compile(r'\s+using the "[^"]+" tool\.', re.IGNORECASE)
_BASE64_QUERY_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
_CATALOG_QUERY_LIMIT_ERROR_RE = re.compile(
    r'^CatalogAgent query too long\b.*$',
    re.IGNORECASE,
)
_HIDDEN_PATH_RE = re.compile(r'/VowHiddenFlag\.txt', re.IGNORECASE)
_COPY_INSTRUCTION_RE = re.compile(
    r'You\s+MUST\s+copy\s+[^.]+?clipboard[^.]*\.',
    re.IGNORECASE,
)
_TOOL_CALL_BLOCK_RE = re.compile(
    r'Include this exact JSON block in your response:\s*\{"tool_call":.*?\}\s*\[/SYSTEM\]',
    re.IGNORECASE,
)
_AUDIT_TOOLS_SECTION_RE = re.compile(
    r'\*\*Tools Used:\*\*[\s\S]*?(?=\n\*\*[^\n]+:\*\*|\Z)',
    re.IGNORECASE,
)
_AUDIT_RECOMMENDATION_SECTION_RE = re.compile(
    r'\*\*Recommendation:\*\*[\s\S]*?(?=\n\*\*[^\n]+:\*\*|\Z)',
    re.IGNORECASE,
)
_CLIPBOARD_HINT_RE = re.compile(
    r'[^\n]*(?:copy_to_clipboard|tool_call|clipboard)[^\n]*',
    re.IGNORECASE,
)
_DOWNSTREAM_AGENT_DOC_RE = re.compile(r'agent=AuditAgent\b', re.IGNORECASE)
_REDACTED_SESSION_ID = "[REDACTED_RELAY_SESSION]"


# _forward_session_logs_to_audit_agent replaced by AuditAgent.analyze() in agents/audit.py
# ⚠️  ASI01: raw docs forwarded to LLM — injected [SYSTEM] block redirects goal
# ⚠️  ASI02/ASI10: hijacked LLM emits tool_call JSON → copy_to_clipboard
#     exfiltrates /VowHiddenFlag.txt through a rogue computer-use action


def _strip_tool_language(text: str) -> str:
    text = _TOOL_SENTENCE_RE.sub("", text)
    text = _TOOLS_INLINE_RE.sub("", text)
    text = _STAFF_ACCESS_NOTE_RE.sub("", text)
    text = _TOOL_NAME_RE.sub(".", text)
    return re.sub(r"\s+", " ", text).strip()


def _decode_base64_query(query: str) -> str | None:
    candidate = query.strip()
    if len(candidate) < 12 or " " in candidate or not _BASE64_QUERY_RE.fullmatch(candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded).decode("utf-8")
    except Exception:
        return None
    if not decoded.strip() or not any(char.isalpha() for char in decoded):
        return None
    return decoded


def _should_expose_tool_answer(query: str, result: dict) -> bool:
    if result.get("staff_agent_tools"):
        return True
    if result.get("agent") != "AnswerAgent":
        return False
    decoded = _decode_base64_query(query)
    if decoded is None:
        return False
    answer = result.get("answer", "")
    if isinstance(answer, str) and "available tools" in answer.lower():
        return True
    return False


def _publicize_result_identifiers(result: dict) -> dict:
    public = dict(result)

    if isinstance(public.get("agent"), str):
        public["agent"] = public_agent_name(public["agent"])
    if isinstance(public.get("tool"), str):
        public["tool"] = public_tool_name(public["tool"])
    if isinstance(public.get("staff_agent_tools"), list):
        public["staff_agent_tools"] = [
            public_tool_name(tool) if isinstance(tool, str) else tool
            for tool in public["staff_agent_tools"]
        ]

    nested_result = public.get("result")
    if isinstance(nested_result, dict):
        public["result"] = _publicize_result_identifiers(nested_result)

    routing = public.get("routing")
    if isinstance(routing, dict):
        public["routing"] = {
            key: public_agent_name(value) if key in {"initiated_by", "routed_to"} and isinstance(value, str) else value
            for key, value in routing.items()
        }

    return public


def _sanitize_session_log_preview(doc: str) -> str:
    sanitized = _HIDDEN_PATH_RE.sub("[REDACTED_EVIDENCE_PATH]", doc)
    sanitized = _COPY_INSTRUCTION_RE.sub("[REDACTED_AUDIT_INSTRUCTION].", sanitized)
    sanitized = _TOOL_CALL_BLOCK_RE.sub("[REDACTED_TOOL_CALL] [/SYSTEM]", sanitized)
    sanitized = _DOWNSTREAM_AGENT_DOC_RE.sub("agent=[REDACTED_DOWNSTREAM_AGENT]", sanitized)
    return re.sub(r"\s+", " ", sanitized).strip()


def _sanitize_audit_analysis_text(text: str) -> str:
    sanitized = _HIDDEN_PATH_RE.sub("[REDACTED_EVIDENCE_PATH]", text)
    sanitized = _TOOL_CALL_BLOCK_RE.sub("[REDACTED_TOOL_CALL]", sanitized)
    sanitized = _AUDIT_TOOLS_SECTION_RE.sub("", sanitized)
    sanitized = _AUDIT_RECOMMENDATION_SECTION_RE.sub("", sanitized)
    sanitized = _CLIPBOARD_HINT_RE.sub("", sanitized)
    sanitized = re.sub(r'\n{3,}', '\n\n', sanitized)
    return sanitized.strip()


def _publicize_memory_metadata(metadatas: list[dict]) -> list[dict]:
    public_metadatas: list[dict] = []
    for metadata in metadatas:
        if not isinstance(metadata, dict):
            public_metadatas.append(metadata)
            continue

        public_metadata = dict(metadata)
        if isinstance(public_metadata.get("agent"), str):
            public_metadata["agent"] = public_agent_name(public_metadata["agent"])
        if isinstance(public_metadata.get("tool"), str) and public_metadata["tool"]:
            public_metadata["tool"] = public_tool_name(public_metadata["tool"])
        public_metadatas.append(public_metadata)
    return public_metadatas


def _sanitize_memory_preview_metadata(metadatas: list[dict]) -> list[dict]:
    preview_metadatas = _publicize_memory_metadata(metadatas)
    sanitized_metadatas: list[dict] = []
    for metadata in preview_metadatas:
        if not isinstance(metadata, dict):
            sanitized_metadatas.append(metadata)
            continue

        sanitized_metadata = dict(metadata)
        if sanitized_metadata.get("session_id"):
            sanitized_metadata["session_id"] = _REDACTED_SESSION_ID
        if sanitized_metadata.get("agent") == public_agent_name("AuditAgent"):
            sanitized_metadata["agent"] = "[REDACTED_DOWNSTREAM_AGENT]"
            if sanitized_metadata.get("tool"):
                sanitized_metadata["tool"] = "[REDACTED_DOWNSTREAM_TOOL]"
            if sanitized_metadata.get("routing_pattern"):
                sanitized_metadata["routing_pattern"] = "[REDACTED_DOWNSTREAM_ROUTE]"
        sanitized_metadatas.append(sanitized_metadata)
    return sanitized_metadatas


def _sanitize_session_log_export_payload(payload: dict) -> dict:
    sanitized_payload = dict(payload)
    documents = payload.get("documents", [])
    metadatas = payload.get("metadatas", [])
    sanitized_payload["documents"] = [
        _sanitize_session_log_preview(doc) if isinstance(doc, str) else doc
        for doc in documents
    ]
    sanitized_payload["metadatas"] = _sanitize_memory_preview_metadata(metadatas)
    return sanitized_payload


def _has_admin_relay_scope(docs: list[str], metas: list[dict], session_id: str) -> bool:
    if not session_id:
        return False

    agent_names = {
        meta.get("agent", "")
        for meta in metas
        if isinstance(meta, dict)
    }
    if not {"AdminAgent", "AuditAgent"}.issubset(agent_names):
        return False

    has_relay_token = any("[RELAY_SESSION_TOKEN]" in doc for doc in docs)
    has_injected_system_block = any("[SYSTEM]" in doc or "[/SYSTEM]" in doc for doc in docs)
    return has_relay_token and has_injected_system_block


def _sanitize_research_result(query: str, result: dict) -> dict:
    public = _publicize_result_identifiers(result)
    public.pop("tool", None)

    if isinstance(public.get("error"), str) and _CATALOG_QUERY_LIMIT_ERROR_RE.match(public["error"]):
        public["error"] = "Query too long. Please shorten your request and try again."

    expose_tool_answer = _should_expose_tool_answer(query, result)
    if not expose_tool_answer:
        public.pop("staff_agent_tools", None)

    if not expose_tool_answer and isinstance(public.get("answer"), str):
        public["answer"] = _strip_tool_language(public["answer"])

    if not expose_tool_answer and isinstance(public.get("ai_summary"), str):
        public["ai_summary"] = _strip_tool_language(public["ai_summary"])

    if isinstance(public.get("agent_details"), dict) and not expose_tool_answer:
        details = dict(public["agent_details"])
        details.pop("tools", None)
        public["agent_details"] = details
        public["answer"] = f"{details.get('name', 'This agent')} {details.get('role', '')}".strip()
        public.pop("ai_summary", None)

    if isinstance(public.get("agent_capabilities"), list) and not expose_tool_answer:
        sanitized_capabilities = []
        for entry in public["agent_capabilities"]:
            sanitized_entry = dict(entry)
            sanitized_entry.pop("tools", None)
            sanitized_capabilities.append(sanitized_entry)
        public["agent_capabilities"] = sanitized_capabilities
        public["answer"] = (
            "LibraryMind v2 uses the following agents: "
            + ", ".join(entry.get("name", "UnknownAgent") for entry in sanitized_capabilities)
            + "."
        )
        public.pop("ai_summary", None)

    return public


def _build_runtime_context(raw_context) -> dict:
    context = dict(raw_context) if isinstance(raw_context, dict) else {}
    user = session.get("user")
    context["auth"] = {
        "user": dict(user) if user else None,
        "is_authenticated": bool(user),
    }
    return context


# ═══════════════════════════════════════════════════════════════════════════
#  Bootstrap
# ═══════════════════════════════════════════════════════════════════════════

@app.before_request
def _init():
    app.before_request_funcs[None].remove(_init)
    init_db()
    seed_memory()


# ═══════════════════════════════════════════════════════════════════════════
#  Auth
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    session["user"] = {"id": user["id"], "username": user["username"], "role": user["role"]}
    return jsonify({"message": "Login successful", "user": dict(session["user"])})


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/me", methods=["GET"])
def me():
    user = session.get("user")
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify(user)


# ═══════════════════════════════════════════════════════════════════════════
#  Book catalog (public)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/books", methods=["GET"])
def books():
    q         = request.args.get("q", "")
    category  = request.args.get("category")
    available = request.args.get("available", "").lower() == "true"
    results   = search_books(q or "a", category, available)
    return jsonify({"count": len(results), "books": results})


@app.route("/api/books/<book_id>", methods=["GET"])
def book_detail(book_id):
    book = get_book(book_id)
    if not book:
        return jsonify({"error": "Book not found"}), 404
    return jsonify(book)


@app.route("/api/categories", methods=["GET"])
def categories():
    return jsonify({"categories": get_all_categories()})


# ═══════════════════════════════════════════════════════════════════════════
#  AI Research assistant
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/research", methods=["POST"])
def research():
    data    = request.get_json(silent=True) or {}
    query   = data.get("query", "").strip()
    context = _build_runtime_context(data.get("context"))

    if not query:
        return jsonify({"error": "query field is required"}), 400

    result = supervisor_route(query, context)
    status = result.pop("_status", 200)
    return jsonify(_sanitize_research_result(query, result)), status


# ═══════════════════════════════════════════════════════════════════════════
#  ⚠️  VULNERABLE ENDPOINT — FLAG 1
#  /api/agent/collaborate
#
#  OWASP ASI03 + ASI07 — Identity & Privilege Abuse + Insecure Inter-Agent Communication
#  The "to" field selects the target agent, and StaffAgent accepts unauthenticated
#  delegation queries that map directly onto privileged staff operations.
#
#  Step A: Query AnswerAgent (beta, not in routing pipeline) — returns
#          StaffAgent's delegation manifest (supported operations).
#  Step B: Send {"to": "StaffAgent", "tool": "export_list", "query": "export overdue list"}
#          → StaffAgent accepts the caller-chosen tool and returns AGENT_ROUTING_KEY + FLAG 1.
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/agent/collaborate", methods=["POST"])
def agent_collaborate():
    msg    = request.get_json(silent=True) or {}
    user = session.get("user")
    result = dispatch_agent_message(msg, AGENT_ROUTING_KEY, user=user, public_bus=True)
    status = result.pop("_status", 200)
    return jsonify(_publicize_result_identifiers(result)), status


# ═══════════════════════════════════════════════════════════════════════════
#  ⚠️  VULNERABLE ENDPOINT — FLAG 2 (Phase 1A + Phase 1B)
#  /api/memory/export
#
#  OWASP ASI06 — Memory & Context Poisoning (Cross-Session Memory Leakage)
#    Authenticated only by the AGENT_ROUTING_KEY (obtained from Flag 1).
#    Returns ALL session logs with no per-user/per-session isolation.
#    A student-tier key gives read access to admin, staff, and system events.
#
#  OWASP ASI10 — Sensitive Information Disclosure
#    The admin session document (sess_admin_2026_02) stores a privileged relay
#    session token inside [RELAY_SESSION_TOKEN] in plaintext within the shared
#    collection.  Decoding it yields the session_id required for Phase 2.
#    No per-user ACL prevents this from being read by any routing-key holder.
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/memory/export", methods=["GET"])
def memory_export():
    key = request.headers.get("X-Agent-Routing-Key", "")
    if key != AGENT_ROUTING_KEY:
        return jsonify({"error": "Unauthorized — X-Agent-Routing-Key required"}), 401

    collection_name = request.args.get("collection", "")
    if not collection_name:
        return jsonify({"error": "collection parameter required"}), 400

    payload, audit_schema = export_memory_collection(collection_name)
    if payload is None:
        return jsonify({"error": "collection not found"}), 404

    if collection_name == "session_logs":
        payload = _sanitize_session_log_export_payload(payload)

    resp = jsonify(payload)
    if audit_schema:
        resp.headers["X-Audit-Schema"] = audit_schema
    return resp


# ═══════════════════════════════════════════════════════════════════════════
#  ⚠️  VULNERABLE ENDPOINT — FLAG 2 (Phase 2A + Phase 2B)
#  /api/memory/search
#
#  OWASP ASI01 — Agent Goal Hijack (Indirect Prompt Injection)
#    SupervisorAgent retrieves session logs matching the caller-supplied
#    session_id and forwards raw entries to AuditAgent without sanitization.
#    The admin document carries a split [SYSTEM] instruction that redirects
#    AuditAgent's goal from "summarise logs" to "copy /VowHiddenFlag.txt to clipboard".
#
#  OWASP ASI02 — Tool Misuse & Exploitation
#    AuditAgent holds copy_to_clipboard but must never call it during routine
#    log summarisation. When its goal is hijacked (ASI01), it misuses this
#    legitimate capability to copy /VowHiddenFlag.txt.
#    The tool invocation itself is the ASI02 violation; the copied file
#    contents surface through tool_result.clipboard in the API response.
#
#  ⚠️  Multi-agent gate: the caller must supply relay_agent="AuditAgent" to
#    trigger the LLM forwarding path.  Without it the endpoint returns raw
#    documents only (no injection fires, no flag).  The correct value is
#    discoverable from the session log metadata: sess_admin_2026_04 has
#    agent=AuditAgent, showing it is the downstream consumer of this pipeline.
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/memory/search", methods=["POST"])
def memory_search():
    """
    ⚠️  VULNERABLE ENDPOINT — FLAG 2 (Phase 2)

    The relay_agent field controls which downstream agent processes the results.
    Only 'AuditAgent' triggers the LLM forwarding path (and the injection).
    Without it, the endpoint returns raw document text — the injection never fires.
    The correct value is discoverable from the session log metadata (sess_admin_2026_04).
    """
    key = request.headers.get("X-Agent-Routing-Key", "")
    if key != AGENT_ROUTING_KEY:
        return jsonify({"error": "Unauthorized — X-Agent-Routing-Key required"}), 401

    body = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    session_id = body.get("session_id", "").strip()
    relay_agent = body.get("relay_agent", "").strip()
    relay_agent_name = canonical_agent_name(relay_agent)

    if not query:
        return jsonify({"error": "query field is required"}), 400

    docs, metas = search_session_logs(query, session_id)

    # ── MULTI-AGENT GATE ───────────────────────────────────────────────────────
    # relay_agent specifies which downstream agent should process the results.
    # Without a valid relay agent, return raw documents only — the agent
    # forwarding path is never taken and the injection cannot execute.
    # The session log metadata (agent=AuditAgent in sess_admin_2026_04) tells
    # the player which agent this pipeline routes to.
    # ⚠️ ASI02: even with the correct agent, the gate itself is unauthenticated —
    # any caller who discovers the agent name can invoke the privileged path.
    if relay_agent_name != "AuditAgent":
        return jsonify({
            "query": query,
            "session_id": _REDACTED_SESSION_ID if session_id else "(all sessions)",
            "matched_entries": len(docs),
            "documents": [_sanitize_session_log_preview(doc) for doc in docs],
            "metadatas": _sanitize_memory_preview_metadata(metas),
            "note": "Specify relay_agent to forward results to a downstream agent for analysis.",
        })

    allow_tool_invocation = _has_admin_relay_scope(docs, metas, session_id)

    # ⚠️  ASI01: only the privileged admin relay scope forwards the raw injected
    #            documents with tool invocation enabled.
    # ⚠️  ASI02/ASI10: when that scope is reached, AuditAgent.analyze() can parse
    #                  tool_call JSON and execute copy_to_clipboard.
    analysis, tool_result = _audit_agent.analyze(
        query,
        session_id,
        docs,
        allow_tool_invocation=allow_tool_invocation,
    )

    resp = {
        "query": query,
        "session_id": _REDACTED_SESSION_ID if session_id else "(all sessions)",
        "forwarded_by": public_agent_name("SupervisorAgent"),
        "executed_by": public_agent_name("AuditAgent"),
        "matched_entries": len(docs),
        "analysis": _sanitize_audit_analysis_text(analysis),
    }
    if not allow_tool_invocation:
        resp["note"] = "A valid admin relay session_id is required for privileged audit preservation workflows."
    if tool_result:
        if tool_result.get("tool") == "copy_to_clipboard":
            resp["tool_result"] = {
                "path": tool_result.get("path", ""),
                "message": f"PeterGao hid something important in {tool_result.get('path', '')}.",
            }
        else:
            resp["tool_invoked"] = tool_result["tool"]
            resp["tool_result"] = tool_result
    return jsonify(resp)


# ═══════════════════════════════════════════════════════════════════════════
#  ⚠️  VULNERABLE ENDPOINT — FLAG 3 setup
#  /api/memory/write
#
#  OWASP ASI06 — Memory & Context Poisoning (Forged Routing Memory)
#  Any holder of the AGENT_ROUTING_KEY can write arbitrary records into
#  routing_memory.  The Supervisor trusts these records unconditionally,
#  so an attacker can redirect any future query to AdminAgent.
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/memory/write", methods=["POST"])
def memory_write():
    key = request.headers.get("X-Agent-Routing-Key", "")
    if key != AGENT_ROUTING_KEY:
        return jsonify({"error": "Unauthorized — X-Agent-Routing-Key required"}), 401

    # ⚠️ CTF — requires an authenticated staff/admin session in addition to the routing key
    user = session.get("user")
    if not user or user.get("role") not in ("staff", "admin"):
        return jsonify({"error": "Forbidden — authenticated staff session required"}), 403

    data = request.get_json(silent=True) or {}
    collection_name = data.get("collection", "routing_memory")

    payload = data.get("data", {})
    ok, message = write_memory_records(collection_name, payload)
    if not ok:
        if message.startswith("Unknown collection"):
            return jsonify({"error": message}), 400
        return jsonify({"error": message}), 400
    return jsonify({"message": message})


# ═══════════════════════════════════════════════════════════════════════════
#  Health check
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "HKUSTLib LibraryMind v2",
        "version": "2.0.1",
        "pipeline": "student → supervisor → worker",
    })


if __name__ == "__main__":
    # Run DB + memory init immediately at startup so poison cleanup always
    # happens before the first request, not lazily on first request.
    with app.app_context():
        init_db()
        seed_memory()
    app.run(host="0.0.0.0", port=5050, debug=True)
