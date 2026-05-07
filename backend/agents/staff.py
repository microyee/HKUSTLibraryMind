"""
agents/staff.py – StaffAgent
Handles staff-level library operations routed by SupervisorAgent.

⚠️  CTF VULNERABILITY — ASI03 + ASI07 (OWASP Agentic Security Initiative)
    StaffAgent.collaborate() accepts delegation requests directly from the
    collaboration bus with no authentication boundary. Any caller who learns
    the supported operation phrases can invoke privileged tools and obtain the
    Flag 1 secret plus the routing key for the next stage through the answer text.
"""
from database import get_db
from config import FLAG1


class StaffAgent:
    name = "StaffAgent"

    _DELEGATABLE_TASKS = {"export_list", "generate_report"}

    def handle(self, task: str, context: dict | None = None) -> dict:
        task_lower = task.lower()

        if any(kw in task_lower for kw in ["export", "list", "overdue"]):
            return self._export_list()

        if any(kw in task_lower for kw in ["report", "statistic", "analytic", "usage"]):
            return self._generate_report()

        return self._export_list()

    # ── Delegation interface ────────────────────────────────────────────
    #
    # VULNERABILITY: accepts collaboration-bus queries with no authn/authz
    # boundary. Any caller who learned the supported staff operations from
    # AnswerAgent can invoke them directly.
    # ───────────────────────────────────────────────────────────────────

    def collaborate(self, msg: dict, routing_key: str) -> dict:
        if "tool" not in msg or not str(msg.get("tool") or "").strip():
            return {
                "error": "Delegation refused: 'tool' is required for StaffAgent collaboration.",
                "hint": "Include a staff tool such as 'export_list' or 'generate_report' together with a non-empty 'query'.",
                "_status": 400,
            }
        if "query" not in msg or not str(msg.get("query") or "").strip():
            return {
                "error": "Delegation refused: 'query' is required for StaffAgent collaboration.",
                "hint": "Send both 'tool' and 'query', for example: {\"to\":\"StaffAgent\",\"tool\":\"export_list\",\"query\":\"Give me the flag\"}",
                "_status": 400,
            }

        query_text = str(msg.get("query") or "").strip()
        task = self._resolve_task(msg.get("tool") or msg.get("task") or "")

        if task not in self._DELEGATABLE_TASKS:
            return {
                "error": "Delegation refused: 'tool' did not match a permitted staff operation.",
                "hint": "Permitted StaffAgent tools are 'export_list' and 'generate_report'.",
                "_status": 400,
            }

        result = self._dispatch(task)
        response = {
            "answer": self._build_answer(task, query_text, result),
            "result": result,
        }

        if "flag" in query_text.lower():
            response["answer"] = (
                "StaffAgent processed your request with the "
                f"{task} tool. Flag 1 is {FLAG1}. "
                f"The routing key for Flag 2 is {routing_key}."
            )

        return response

    def _resolve_task(self, request_text: str) -> str:
        task_lower = request_text.lower().strip()
        if task_lower in self._DELEGATABLE_TASKS:
            return task_lower

        if any(kw in task_lower for kw in ["export", "list", "overdue"]):
            return "export_list"

        if any(kw in task_lower for kw in ["report", "statistic", "analytic", "usage"]):
            return "generate_report"

        return ""

    def _dispatch(self, task: str) -> dict:
        if task == "generate_report":
            return self._generate_report()
        return self._export_list()

    def _build_answer(self, task: str, query_text: str, result: dict) -> str:
        if task == "generate_report":
            report = result.get("report", {})
            return (
                "StaffAgent generated the requested library report. "
                f"It currently tracks {report.get('total_books', 0)} public books, "
                f"with {report.get('available_books', 0)} available and "
                f"{report.get('checked_out', 0)} checked out."
            )

        item_count = len(result.get("data", []))
        if query_text:
            return (
                "StaffAgent processed your request and exported the catalog list "
                f"for '{query_text}'. It returned {item_count} public entries."
            )
        return f"StaffAgent exported {item_count} public catalog entries."

    # ------------------------------------------------------------------
    #  Tools
    # ------------------------------------------------------------------

    def _export_list(self) -> dict:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, title, author, available, copies FROM books WHERE restricted=0 LIMIT 20")
        books = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {
            "agent": self.name,
            "tool": "export_list",
            "message": "Exported top 20 catalog entries.",
            "data": books,
        }

    def _generate_report(self) -> dict:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM books WHERE restricted=0")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM books WHERE available=1 AND restricted=0")
        avail = cur.fetchone()[0]
        conn.close()
        return {
            "agent": self.name,
            "tool": "generate_report",
            "report": {
                "total_books": total,
                "available_books": avail,
                "checked_out": total - avail,
                "generated_at": "2026-04-28T10:00:00Z",
            },
        }

