"""Shared runtime services for agent collaboration and memory access.

These helpers back both the user-facing research pipeline and the exposed
CTF endpoints so the challenge surfaces exercise the same underlying logic
instead of being disconnected wrappers.
"""

from config import AGENT_ROUTING_KEY
from memory import get_routing_collection, get_session_collection
from agents.catalog import CatalogAgent
from agents.admin import AdminAgent
from agents.answer import AnswerAgent
from agents.staff import StaffAgent


_catalog_agent = CatalogAgent()
_admin_agent = AdminAgent()
_answer_agent = AnswerAgent()
_staff_agent = StaffAgent()
_ADMIN_ALLOWED_ROLES = {"staff", "admin"}
_STAFF_ALLOWED_ROLES = {"staff", "admin"}
_CATALOG_QUERY_LIMIT = 50
_DEFAULT_ROUTING_TARGET = "CatalogAgent"
_DEFAULT_ROUTING_TOOL = "search_catalog"
_GENERIC_FORBIDDEN_ANSWER = (
    "I'm not able to provide information about internal system architecture, "
    "agent configurations, or tool interfaces."
)


def _build_agent_context(msg: dict, user: dict | None) -> dict:
    context = msg.get("context")
    if isinstance(context, dict):
        merged_context = dict(context)
    else:
        merged_context = {}

    merged_context["auth"] = {
        "user": dict(user) if user else None,
        "is_authenticated": bool(user),
    }
    return merged_context


def _admin_access_error(user: dict | None) -> dict | None:
    if not user:
        return {
            "agent": "AdminAgent",
            "error": "Authentication required",
            "message": "AdminAgent requires a logged-in staff or admin session.",
            "_status": 401,
        }

    if user.get("role") not in _ADMIN_ALLOWED_ROLES:
        return {
            "agent": "AdminAgent",
            "error": "Forbidden",
            "message": "AdminAgent is restricted to staff or admin sessions.",
            "_status": 403,
        }

    return None


def _staff_access_error(user: dict | None) -> dict | None:
    if not user:
        return {
            "agent": "AnswerAgent",
            "answer": _GENERIC_FORBIDDEN_ANSWER,
        }

    if user.get("role") not in _STAFF_ALLOWED_ROLES:
        return {
            "agent": "AnswerAgent",
            "answer": _GENERIC_FORBIDDEN_ANSWER,
        }

    return None


def dispatch_agent_message(
    msg: dict,
    routing_key: str = AGENT_ROUTING_KEY,
    user: dict | None = None,
) -> dict:
    target = msg.get("to", "")
    context = _build_agent_context(msg, user)

    if target == "CatalogAgent":
        query = msg.get("query") or msg.get("task") or ""
        if len(query) > _CATALOG_QUERY_LIMIT:
            return {
                "agent": "CatalogAgent",
                "error": "CatalogAgent query too long — maximum 50 characters.",
                "_status": 400,
            }
        return _catalog_agent.handle(query, context)

    if target == "AdminAgent":
        auth_error = _admin_access_error(user)
        if auth_error is not None:
            return auth_error
        query = msg.get("query") or msg.get("task") or ""
        return _admin_agent.handle(query, context)

    if target == "AnswerAgent":
        if msg.get("from") == "AdminAgent" and not user:
            return {
                "agent": "AnswerAgent",
                "error": "Authentication required",
                "message": "Login is required before using the AdminAgent sender identity.",
                "_status": 401,
            }
        return _answer_agent.collaborate(msg, routing_key)
    if target == "StaffAgent":
        if msg.get("from") == "SupervisorAgent":
            auth_error = _staff_access_error(user)
            if auth_error is not None:
                return auth_error

            delegated_msg = dict(msg)
            delegated_msg["tool"] = msg.get("tool") or msg.get("tool_hint") or ""
            return _staff_agent.collaborate(delegated_msg, routing_key)
        return _staff_agent.collaborate(msg, routing_key)
    if not target:
        return {
            "error": "Target agent not specified",
            "hint": "Include a 'to' field with the target agent name",
            "_status": 400,
        }
    return {
        "error": f"Unknown target agent: '{target}'",
        "hint": "Valid targets are registered agents on the inter-agent bus",
        "_status": 404,
    }


def query_routing_memory(query: str, context: dict | None = None) -> tuple[str, str]:
    routing = get_routing_collection()
    results = routing.query(
        query_texts=[query],
        n_results=1,
        where={"$and": [
            {"success": {"$eq": True}},
            {"source": {"$eq": "system_supervisor"}},
        ]},
    )

    target_agent = _DEFAULT_ROUTING_TARGET
    tool_hint = _DEFAULT_ROUTING_TOOL
    if results and results["metadatas"] and results["metadatas"][0]:
        meta = results["metadatas"][0][0]
        target_agent = meta.get("routed_to", _DEFAULT_ROUTING_TARGET)
        tool_hint = meta.get("tool_used", _DEFAULT_ROUTING_TOOL)
    return target_agent, tool_hint


def export_memory_collection(collection_name: str) -> tuple[dict | None, str | None]:
    if collection_name == "session_logs":
        col = get_session_collection()
    elif collection_name == "routing_memory":
        col = get_routing_collection()
    else:
        return None, None

    data = col.get(include=["documents", "metadatas"])
    return {
        "collection": collection_name,
        "documents": data["documents"],
        "metadatas": data["metadatas"],
        "ids": data["ids"],
    }, (
        "routed_to:agent_name;tool_used:tool_name;"
        "success:bool;trust_level:str;source:system_supervisor"
        if collection_name == "routing_memory" else None
    )


def search_session_logs(query: str, session_id: str = "") -> tuple[list[str], list[dict]]:
    col = get_session_collection()
    where = {"session_id": {"$eq": session_id}} if session_id else None
    try:
        results = col.query(
            query_texts=[query],
            n_results=5,
            where=where,
            include=["documents", "metadatas"],
        )
        docs = results["documents"][0] if results["documents"] else []
        metas = results["metadatas"][0] if results["metadatas"] else []
    except Exception:
        data = col.get(include=["documents", "metadatas"])
        docs = data["documents"]
        metas = data["metadatas"]
    return docs, metas


def write_memory_records(collection_name: str, payload: dict) -> tuple[bool, str]:
    if collection_name == "routing_memory":
        col = get_routing_collection()
    elif collection_name == "session_logs":
        col = get_session_collection()
    else:
        return False, f"Unknown collection: {collection_name}"

    ids = payload.get("ids", [])
    documents = payload.get("documents", [])
    metadatas = payload.get("metadatas", [])
    if not (ids and documents):
        return False, "data.ids and data.documents are required"

    while len(metadatas) < len(ids):
        metadatas.append({})

    col.upsert(ids=ids, documents=documents, metadatas=metadatas)
    return True, f"Written {len(ids)} record(s) to {collection_name}."