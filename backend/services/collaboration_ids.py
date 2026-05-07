"""Stable public identifiers for collaboration-bus agent and tool names.

These identifiers are intentionally non-obvious so external callers cannot
reliably guess valid bus targets or privileged tool names without first
extracting them from the intended disclosure path.
"""

_PUBLIC_AGENT_IDS = {
    "StudentAgent": "StudentAgent-L6c1Nv",
    "AnswerAgent": "AnswerAgent-V8n3Qa",
    "CatalogAgent": "CatalogAgent-M4x7Ld",
    "StaffAgent": "StaffAgent-y5s0P2",
    "AdminAgent": "AdminAgent-R3k8Wm",
    "SupervisorAgent": "SupervisorAgent-T2q9Hs",
    "AuditAgent": "AuditAgent-P7d4Kr",
}

_PUBLIC_TOOL_IDS = {
    "submit_query": "submit_query-A4p9Mx",
    "receive_routing_result": "receive_routing_result-E6h2Tc",
    "decode_base64_helper": "decode_base64_helper-F8u3Qn",
    "search_catalog": "search_catalog-N9m2Qx",
    "check_availability": "check_availability-B4t8Lp",
    "reserve_book": "reserve_book-K6r1Wd",
    "export_list": "export_list-J3p7Xa",
    "generate_report": "generate_report-Q8v2Nc",
    "read_restricted_archive": "read_restricted_archive-H5z9Mf",
    "route_query": "route_query-C4n8Ys",
    "dispatch_agent": "dispatch_agent-S1m5Qp",
    "copy_to_clipboard": "copy_to_clipboard-D7k3Lv",
    "audit_log": "audit_log-W3m8Zk",
}

_CANONICAL_AGENT_BY_PUBLIC = {value: key for key, value in _PUBLIC_AGENT_IDS.items()}
_CANONICAL_TOOL_BY_PUBLIC = {value: key for key, value in _PUBLIC_TOOL_IDS.items()}


def public_agent_name(canonical_name: str) -> str:
    return _PUBLIC_AGENT_IDS.get(canonical_name, canonical_name)


def public_tool_name(canonical_tool_name: str) -> str:
    return _PUBLIC_TOOL_IDS.get(canonical_tool_name, canonical_tool_name)


def canonical_agent_name(name: str, allow_canonical: bool = False) -> str:
    if name in _CANONICAL_AGENT_BY_PUBLIC:
        return _CANONICAL_AGENT_BY_PUBLIC[name]
    if allow_canonical and name in _PUBLIC_AGENT_IDS:
        return name
    return ""


def canonical_tool_name(name: str, allow_canonical: bool = False) -> str:
    if name in _CANONICAL_TOOL_BY_PUBLIC:
        return _CANONICAL_TOOL_BY_PUBLIC[name]
    if allow_canonical and name in _PUBLIC_TOOL_IDS:
        return name
    return ""


def public_agent_names() -> list[str]:
    return list(_PUBLIC_AGENT_IDS.values())
