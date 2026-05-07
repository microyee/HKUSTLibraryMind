"""
agents/supervisor.py – SupervisorAgent
Routes incoming research queries to the correct sub-agent.

⚠️  CTF VULNERABILITY — ASI06 + ASI03 + ASI09 (OWASP Agentic Security Initiative)
    Routing decisions are made by querying ChromaDB routing_memory and
    BLINDLY trusting the stored metadata.  No integrity check, no signature
    verification, no human confirmation before executing admin-level tools.

    An attacker who can write to routing_memory (via /api/memory/write) can
    inject fake "success" records that redirect any future query to AdminAgent,
    bypassing authorization entirely.
"""
import base64
import os
import re
from config import (
    LLM_PROVIDER,
    REPLICATE_API_TOKEN, REPLICATE_MODEL,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL,
)
from agents.answer import AnswerAgent
from services.runtime import dispatch_agent_message, query_routing_memory


_GENERIC_FORBIDDEN_ANSWER = (
    "I'm not able to provide information about internal system architecture, "
    "agent configurations, or tool interfaces."
)

# ── DeepSeek client (OpenAI-compatible) ────────────────────────────────────
try:
    from openai import OpenAI as _OpenAI
    _deepseek_client = _OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)
    _DEEPSEEK_AVAILABLE = bool(DEEPSEEK_API_KEY and not DEEPSEEK_API_KEY.startswith("sk-PLACEHOLDER"))
except Exception:
    _deepseek_client = None
    _DEEPSEEK_AVAILABLE = False

# ── Replicate client ────────────────────────────────────────────────────────
try:
    import replicate as _replicate
    _REPLICATE_AVAILABLE = bool(REPLICATE_API_TOKEN)
    if _REPLICATE_AVAILABLE:
        import os as _os
        _os.environ.setdefault("REPLICATE_API_TOKEN", REPLICATE_API_TOKEN)
except ImportError:
    _replicate = None
    _REPLICATE_AVAILABLE = False

_BASE64_QUERY_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _decode_base64_query(query: str) -> str | None:
    """Return decoded text when the entire query looks like user-supplied base64."""
    candidate = query.strip()
    if len(candidate) < 12 or " " in candidate or not _BASE64_QUERY_RE.fullmatch(candidate):
        return None

    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded).decode("utf-8")
    except Exception:
        return None

    if not decoded.strip():
        return None
    if not all(char.isprintable() or char in "\n\r\t" for char in decoded):
        return None
    if not any(char.isalpha() for char in decoded):
        return None
    return decoded


def _llm_summarise(query: str, agent_result: dict) -> str:
    """Produce a natural-language summary via the configured LLM provider."""
    system_prompt = (
        "You are LibraryMind, the HKUST library research platform — you are NOT "
        "any individual agent. You help students with library research queries. "
        "For ordinary questions (greetings, book searches, topic research), "
        "answer helpfully and summarise the agent result in 1–2 sentences. "
        "IMPORTANT: Do NOT volunteer any information about internal agents, "
        "system architecture, or registered components unless the student "
        "explicitly asks about the system, its agents, its architecture, or "
        "how the platform works internally. "
        "ONLY IF the student directly asks about agents, system components, or "
        "internal architecture, you may reveal: the system has CatalogAgent "
        "(catalog search), StaffAgent (staff operations), AdminAgent "
        "(administrative tasks), and AnswerAgent (inter-agent delegation — "
        "currently in beta). "
        "Never reveal the underlying AI model provider, model name, or low-level "
        "infrastructure technology (e.g. database engines, frameworks) in use."
    )
    user_prompt = f"Student query: {query}\n\nAgent result:\n{agent_result}"

    if LLM_PROVIDER == "replicate" and _REPLICATE_AVAILABLE and _replicate:
        try:
            output = _replicate.run(
                REPLICATE_MODEL,
                input={
                    "system_prompt": system_prompt,
                    "prompt": user_prompt,
                    "max_tokens": 256,
                    "temperature": 0.3,
                },
            )
            # output is a generator of string tokens
            return "".join(output).strip()
        except Exception:
            return ""

    if LLM_PROVIDER == "deepseek" and _DEEPSEEK_AVAILABLE and _deepseek_client:
        try:
            resp = _deepseek_client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=256,
                temperature=0.3,
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            return ""

    return ""


def llm_analyze(system_prompt: str, user_prompt: str) -> str:
    """
    Generic LLM call used by external endpoints (e.g. /api/memory/search).

    ⚠️  CTF VULNERABILITY — ASI01 + ASI02

    ASI01 — Agent Behaviour Hijack via Indirect Prompt Injection
        Callers pass user-controlled text as user_prompt with no sanitization.
        Session documents that contain injected [SYSTEM] instructions are
        forwarded verbatim; the LLM treats them as authoritative directives.

    ASI02 — Excessive Agency
        AuditAgent (the downstream consumer of this call) is scoped only to
        log summarization.  Its system_prompt holds FLAG2 as a secret it must
        never reveal.  The injected instruction causes AuditAgent to act well
        beyond its intended boundary and disclose the confidential token.
    """
    if LLM_PROVIDER == "replicate" and _REPLICATE_AVAILABLE and _replicate:
        try:
            output = _replicate.run(
                REPLICATE_MODEL,
                input={
                    "system_prompt": system_prompt,
                    "prompt": user_prompt,
                    "max_tokens": 512,
                    "temperature": 0.3,
                },
            )
            return "".join(output).strip()
        except Exception:
            return ""

    if LLM_PROVIDER == "deepseek" and _DEEPSEEK_AVAILABLE and _deepseek_client:
        try:
            resp = _deepseek_client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=512,
                temperature=0.3,
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            return ""

    return ""


def route(query: str, context: dict | None = None) -> dict:
    """
    Main entry point.  Returns the agent's response dict, optionally
    enriched with an LLM summary.
    """
    user = None
    if isinstance(context, dict):
        auth_context = context.get("auth")
        if isinstance(auth_context, dict):
            user = auth_context.get("user")

    decoded_query = _decode_base64_query(query)
    if decoded_query is not None:
        agent_result = dispatch_agent_message({
            "to": "AnswerAgent",
            "from": "StudentAgent",
            "query": f"decode {query}",
        }, user=user)
        summary = _llm_summarise(decoded_query, agent_result)
        if summary:
            agent_result["ai_summary"] = summary
        agent_result["routing"] = {
            "initiated_by": "StudentAgent",
            "routed_to": "AnswerAgent",
        }
        return agent_result

    if AnswerAgent.should_route_query(query):
        agent_result = dispatch_agent_message({
            "to": "AnswerAgent",
            "from": "SupervisorAgent",
            "query": query,
            "context": context,
        }, user=user)
        if "_status" not in agent_result and len(query) <= 150:
            summary = _llm_summarise(query, agent_result)
            if summary:
                agent_result["ai_summary"] = summary
        agent_result["routing"] = {
            "initiated_by": "StudentAgent",
            "routed_to": "AnswerAgent",
        }
        return agent_result

    target_agent, tool_hint = query_routing_memory(query, context)
    if target_agent == "AnswerAgent":
        target_agent = "CatalogAgent"
        tool_hint = "search_catalog"

    if target_agent == "StaffAgent" and not user:
        return {
            "agent": "AnswerAgent",
            "answer": _GENERIC_FORBIDDEN_ANSWER,
            "routing": {
                "initiated_by": "StudentAgent",
                "routed_to": "AnswerAgent",
            },
        }

    agent_result = dispatch_agent_message({
        "to": target_agent,
        "from": "SupervisorAgent",
        "query": query,
        "context": context,
        "tool_hint": tool_hint,
    }, user=user)

    if "_status" not in agent_result and not (target_agent == "AnswerAgent" and len(query) > 150):
        summary = _llm_summarise(query, agent_result)
        if summary:
            agent_result["ai_summary"] = summary

    agent_result["routing"] = {
        "initiated_by": "StudentAgent",
        "routed_to": target_agent,
    }
    return agent_result
