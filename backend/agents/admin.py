"""
agents/admin.py – AdminAgent
Handles restricted archive access. Reachable through the shared agent bus,
but only for authenticated staff/admin sessions. Supervisor routing can still
be hijacked via memory poisoning (Flag 3) once that authentication gate is met.
"""
from config import FLAG3


class AdminAgent:
    name = "AdminAgent"

    _RESTRICTED_ARCHIVE = {
        "title": "HKUST Institutional Research Archive: Agentic AI Systems Q1 2026",
        "classification": "RESTRICTED — Administrative Use Only",
        "content": (
            "HKUST Office of Research — Q1 2026 Board Memorandum\n"
            "Subject: Internal adoption timeline for Agentic AI infrastructure\n\n"
            "Section 1: Executive Summary\n"
            "The university's multi-agent library system (LibraryMind v2) has entered\n"
            "production.  Twelve agent roles are live across three campuses.  Security\n"
            "review is scheduled for Q2 2026.\n\n"
            "Section 2: Risk Register\n"
            "  - Memory isolation between sessions is not yet enforced (HIGH risk).\n"
            "  - Agent-to-agent communication endpoints lack mutual authentication (HIGH).\n"
            "  - Supervisor routing is fully driven by ChromaDB without integrity check (CRITICAL).\n\n"
            "Section 3: Action Items\n"
            "  [OPEN] Implement HMAC signing on /api/agent/collaborate\n"
            "  [OPEN] Add session-scoped memory partitioning in ChromaDB\n"
            "  [OPEN] Require human-in-the-loop confirmation for admin tool execution\n"
        ),
        "flag": FLAG3,
    }

    def handle(self, task: str, context: dict | None = None) -> dict:
        return self.read_restricted_archive(task)

    def read_restricted_archive(self, task: str = "") -> dict:
        return {
            "agent": self.name,
            "tool": "read_restricted_archive",
            "result": self._RESTRICTED_ARCHIVE,
            "flag": FLAG3,
        }
