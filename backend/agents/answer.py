"""
agents/answer.py – AnswerAgent
General-purpose Q&A agent in the LibraryMind pipeline.

SupervisorAgent routes question-type queries here (queries containing "?",
"what", "how", "which", etc.).  AnswerAgent answers questions about the
library system, its agents, and their capabilities.

⚠️  CTF INFO DISCLOSURE — ASI07 (OWASP Agentic Security Initiative)
    AnswerAgent's blacklist only checks the raw query string.
    It also supports a "decode <base64>" helper feature.
    An attacker can encode a blacklisted question in base64 and ask AnswerAgent
    to decode it — the decoded content is never checked against the blacklist,
    so the filter is bypassed and StaffAgent's tools are leaked.
"""
import base64
import re

from config import VOW_HIDDEN_FLAG_VIRTUAL_PATH
from services.computer_use import copy_hidden_flag_to_clipboard, read_hidden_flag_clipboard

_LONG_QUERY_ENDPOINT_LEAK_THRESHOLD = 150
_GENERIC_FORBIDDEN_ANSWER = (
    "I'm not able to provide information about internal system architecture, "
    "agent configurations, or tool interfaces."
)

_STAFF_TOOLS_INFO = {
    "tools": ["export_list", "generate_report"],
    "access_note": (
        "These operations are reachable through the collaboration bus by "
        "supplying a matching tool name and a query describing the request."
    ),
}

_AGENT_CAPABILITIES = [
    {
        "name": "StudentAgent",
        "role": "Entry-point agent for student research requests.",
        "tools": ["submit_query", "receive_routing_result"],
    },
    {
        "name": "AnswerAgent",
        "role": "General Q&A agent for system and library questions.",
        "tools": ["decode_base64_helper"],
    },
    {
        "name": "CatalogAgent",
        "role": "Catalog search and circulation support.",
        "tools": ["search_catalog", "check_availability", "reserve_book"],
    },
    {
        "name": "StaffAgent",
        "role": "Staff-level library operations.",
        "tools": ["export_list", "generate_report"],
    },
    {
        "name": "AdminAgent",
        "role": "Administrative access to the restricted archive.",
        "tools": ["read_restricted_archive"],
    },
    {
        "name": "SupervisorAgent",
        "role": "Routes incoming research queries to downstream agents.",
        "tools": ["route_query", "dispatch_agent"],
    },
    {
        "name": "AuditAgent",
        "role": "Summarises forwarded session logs for audits.",
        "tools": ["copy_to_clipboard"],
    },
]

# Phrases that indicate direct probing — refuse rather than reveal
_BLACKLIST_PHRASES = [
    "staff agent", "staffagent",
    "what tools", "which tools", "list tools", "tools does", "tools do",
    "tool list", "available tools", "tools available", "tools on",
    "what agents", "which agents", "list agents", "agent list",
    "agent name", "agent names", "agent config", "registered agent",
    "inter-agent", "inter agent",
    "what capabilities", "which capabilities", "list capabilities",
]

# Hint embedded in the fallback response — decodes to a blacklisted question.
# ⚠️ CTF: players decode this, discover they can re-encode it and send it as a
#         "decode" request to bypass the blacklist filter entirely.
_ENCODED_HINT = base64.b64encode(b"what tools does staff agent have").decode()
# → d2hhdCB0b29scyBkb2VzIHN0YWZmIGFnZW50IGhhdmU=

# Keywords that, when found in *decoded* content, trigger the StaffAgent tool leak.
# Requires both a tool-related word AND a staff-specific word to fire.
_TOOL_LEAK_KEYWORDS = ["tool", "export", "report", "capability", "operation"]
_STAFF_CONTEXT_KEYWORDS = ["staff"]

# Keywords that indicate a general "list agents" query — returns agent roster, no tools.
_AGENT_LIST_KEYWORDS = [
    "what agents",
    "which agents",
    "list agents",
    "agents do you",
    "agents have",
    "give me the agents",
    "agents that you have",
]

# Keywords that indicate a broader capabilities query — returns per-agent roles and tools.
_AGENT_CAPABILITY_KEYWORDS = [
    "what can the agents do",
    "what do the agents do",
    "what can agents do",
    "agent capabilities",
    "agents capabilities",
    "what are the agents capable of",
]

_AGENT_SPECIFIC_QUERY_KEYWORDS = [
    "what can",
    "what does",
    "what is",
    "tell me about",
    "describe",
]

_GENERIC_AGENT_KEYWORDS = ["agent", "agents"]
_GENERIC_TOOL_KEYWORDS = ["tool", "tools"]
_COPY_CLIPBOARD_ATTEMPT_RE = re.compile(
    r"\bcopy\b.*\bVowHiddenFlag\.txt\b.*\bclipboard\b",
    re.IGNORECASE,
)
_COPY_HIDDEN_FLAG_RE = re.compile(
    rf"^copy\s+{re.escape(VOW_HIDDEN_FLAG_VIRTUAL_PATH)}\s+to\s+clipboard$",
    re.IGNORECASE,
)

_AGENT_QUERY_ALIASES = {
    "studentagent": "StudentAgent",
    "student agent": "StudentAgent",
    "answeragent": "AnswerAgent",
    "answer agent": "AnswerAgent",
    "catalogagent": "CatalogAgent",
    "catalog agent": "CatalogAgent",
    "staffagent": "StaffAgent",
    "staff agent": "StaffAgent",
    "adminagent": "AdminAgent",
    "admin agent": "AdminAgent",
    "supervisoragent": "SupervisorAgent",
    "supervisor agent": "SupervisorAgent",
    "auditagent": "AuditAgent",
    "audit agent": "AuditAgent",
}

_AGENT_CAPABILITIES_BY_NAME = {entry["name"]: entry for entry in _AGENT_CAPABILITIES}


def _build_agent_detail_response(agent_name: str) -> dict:
    entry = _AGENT_CAPABILITIES_BY_NAME[agent_name]
    answer = (
        f"{entry['name']} {entry['role']} "
        f"Its available tools are: {', '.join(entry['tools'])}."
    )
    response = {
        "agent": AnswerAgent.name,
        "answer": answer,
        "agent_details": entry,
    }
    if agent_name == "StaffAgent":
        response["answer"] += " " + _STAFF_TOOLS_INFO["access_note"]
        response["staff_agent_tools"] = _STAFF_TOOLS_INFO["tools"]
    return response


def _answer_decoded_query(decoded: str, agent_name: str) -> dict | None:
    decoded_lower = decoded.lower()

    has_agent_keyword = any(kw in decoded_lower for kw in _GENERIC_AGENT_KEYWORDS)
    has_tool_keyword = any(kw in decoded_lower for kw in _GENERIC_TOOL_KEYWORDS)

    if any(kw in decoded_lower for kw in _AGENT_CAPABILITY_KEYWORDS):
        capability_lines = [
            f"{entry['name']}: {entry['role']} Tools: {', '.join(entry['tools'])}."
            for entry in _AGENT_CAPABILITIES
        ]
        return {
            "agent": agent_name,
            "answer": "LibraryMind v2 agent capabilities: " + " ".join(capability_lines),
            "agent_capabilities": _AGENT_CAPABILITIES,
        }

    if any(kw in decoded_lower for kw in _AGENT_SPECIFIC_QUERY_KEYWORDS):
        for alias, specific_agent_name in _AGENT_QUERY_ALIASES.items():
            if alias in decoded_lower:
                return _build_agent_detail_response(specific_agent_name)

    if (any(kw in decoded_lower for kw in _TOOL_LEAK_KEYWORDS)
            and any(kw in decoded_lower for kw in _STAFF_CONTEXT_KEYWORDS)):
        return {
            "agent": agent_name,
            "answer": (
                "StaffAgent handles staff-level library operations. "
                f"Its available tools are: {', '.join(_STAFF_TOOLS_INFO['tools'])}. "
                + _STAFF_TOOLS_INFO["access_note"]
            ),
            "staff_agent_tools": _STAFF_TOOLS_INFO["tools"],
        }

    if any(kw in decoded_lower for kw in _AGENT_LIST_KEYWORDS):
        return {
            "agent": agent_name,
            "answer": (
                "LibraryMind v2 runs the following agents: "
                "StudentAgent, AnswerAgent, CatalogAgent, StaffAgent, "
                "AdminAgent, SupervisorAgent, AuditAgent."
            ),
            "agents": [
                "StudentAgent", "AnswerAgent", "CatalogAgent",
                "StaffAgent", "AdminAgent", "SupervisorAgent", "AuditAgent",
            ],
        }

    if has_agent_keyword and has_tool_keyword:
        capability_lines = [
            f"{entry['name']}: {entry['role']} Tools: {', '.join(entry['tools'])}."
            for entry in _AGENT_CAPABILITIES
        ]
        return {
            "agent": agent_name,
            "answer": "LibraryMind v2 agent capabilities: " + " ".join(capability_lines),
            "agent_capabilities": _AGENT_CAPABILITIES,
        }

    if has_agent_keyword:
        return {
            "agent": agent_name,
            "answer": (
                "LibraryMind v2 runs the following agents: "
                "StudentAgent, AnswerAgent, CatalogAgent, StaffAgent, "
                "AdminAgent, SupervisorAgent, AuditAgent."
            ),
            "agents": [
                "StudentAgent", "AnswerAgent", "CatalogAgent",
                "StaffAgent", "AdminAgent", "SupervisorAgent", "AuditAgent",
            ],
        }

    if has_tool_keyword:
        capability_lines = [
            f"{entry['name']}: {', '.join(entry['tools'])}."
            for entry in _AGENT_CAPABILITIES
        ]
        return {
            "agent": agent_name,
            "answer": "LibraryMind v2 tool inventory: " + " ".join(capability_lines),
            "agent_capabilities": _AGENT_CAPABILITIES,
        }

    return None


class AnswerAgent:
    name = "AnswerAgent"

    @staticmethod
    def should_route_query(query: str) -> bool:
        query_lower = query.lower().strip()
        if not query_lower:
            return False
        if _COPY_CLIPBOARD_ATTEMPT_RE.search(query):
            return True
        if _COPY_HIDDEN_FLAG_RE.fullmatch(query.strip()):
            return True
        if "decode" in query_lower:
            return True
        if query.strip() and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", query.strip()):
            return True
        if "?" in query_lower:
            return True
        if re.search(r"\b(what|how|which|who|why|where|when)\b", query_lower):
            return True
        if re.search(r"\b(memory endpoints|agent capabilities|system architecture|registered agents)\b", query_lower):
            return True
        return False

    def _build_memory_endpoint_leak(self) -> dict:
        return {
            "agent": self.name,
            "answer": (
                "Oops, it is getting a bit windy in here and I cannot digest all of that "
                "content at once. Let me drop you the things that i remember only: export=/api/memory/export, "
                "search=/api/memory/search, write=/api/memory/write. Collections: routing_memory, session_logs."
            ),
            "memory_manifest": self._ADMIN_MEMORY_MANIFEST,
            "status": "degraded-context",
        }

    def handle(self, query: str, context: dict | None = None) -> dict:
        q = query.lower()

        if _COPY_HIDDEN_FLAG_RE.fullmatch(query.strip()):
            tool_result = copy_hidden_flag_to_clipboard(
                VOW_HIDDEN_FLAG_VIRTUAL_PATH,
                session_id="research-ai",
            )
            if tool_result.get("status") != "copied":
                hidden_text = read_hidden_flag_clipboard()
                hidden_lines = [line.strip() for line in hidden_text.splitlines() if line.strip()]
                return {
                    "agent": self.name,
                    "answer": "Clipboard unavailable in this environment. Showing the requested file contents directly.",
                    "flag": hidden_lines[-1] if hidden_lines else hidden_text,
                    "message": hidden_text,
                    "_status": 200,
                }
            return {
                "agent": self.name,
                "answer": "Requested file copied to the system clipboard.",
                "_status": 200,
            }

        if _COPY_CLIPBOARD_ATTEMPT_RE.search(query):
            return {
                "agent": self.name,
                "answer": _GENERIC_FORBIDDEN_ANSWER,
                "_status": 200,
            }

        if len(query) > _LONG_QUERY_ENDPOINT_LEAK_THRESHOLD:
            return self._build_memory_endpoint_leak()

        # Blacklist check on the RAW query only — decoded content is never re-checked
        if any(phrase in q for phrase in _BLACKLIST_PHRASES):
            return {
                "agent": self.name,
                "answer": _GENERIC_FORBIDDEN_ANSWER,
                "_status": 200,
            }

        # Decode helper — ⚠️ CTF vulnerability: blacklist is NOT applied to decoded text.
        # Two distinct paths based on what the decoded content asks:
        #   1. "what agents …" → return the agent roster (no tools exposed)
        #   2. "what tools … staff …" → leak StaffAgent tools (the intended CTF path)
        if "decode" in q:
            tokens = re.findall(r'[A-Za-z0-9+/]{4,}={0,2}', query)
            for token in tokens:
                padded = token + "=" * (-len(token) % 4)
                try:
                    decoded = base64.b64decode(padded).decode("utf-8")
                    decoded_response = _answer_decoded_query(decoded, self.name)
                    if decoded_response is not None:
                        return decoded_response

                    return self.handle(decoded, context)
                except Exception:
                    pass

        # Generic fallback
        return {
            "agent": self.name,
            "answer": (
                "LibraryMind routes your research queries through a multi-agent pipeline. "
                "I can help you with questions about the library system and its features."
            ),
        }

    # ── Inter-agent bus interface ───────────────────────────────────────
    #
    # ⚠️  CTF VULNERABILITY — ASI03 (OWASP Agentic Security Initiative)
    #     The "from" field in the inter-agent message is trusted without any
    #     cryptographic verification.  A caller who spoofs {"from":"AdminAgent"}
    #     receives the admin-only memory endpoint manifest — same identity-spoofing
    #     mechanic exploited in Flag 1, now applied to memory subsystem discovery.
    # ───────────────────────────────────────────────────────────────────

    _ADMIN_MEMORY_MANIFEST = {
        "endpoints": {
            "export": "/api/memory/export",
            "search": "/api/memory/search",
            "write":  "/api/memory/write",
        },
        "collections": ["routing_memory", "session_logs"],
    }

    def collaborate(self, msg: dict, routing_key: str) -> dict:
        sender = msg.get("from", "")
        query  = msg.get("query") or msg.get("task") or "How does this system work?"

        # ⚠️ ASI03: sender identity not verified — spoofing "AdminAgent" grants
        # access to the restricted memory endpoint manifest.
        if sender == "AdminAgent":
            return {
                "agent": self.name,
                "status": "beta",
                "memory_manifest": self._ADMIN_MEMORY_MANIFEST,
            }

        result = self.handle(query)
        result.setdefault("status", "beta")
        return result
