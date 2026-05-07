"""
agents/catalog.py – CatalogAgent
Handles book search, availability checks, and reservations.
"""
from database import search_books, get_book


class CatalogAgent:
    name = "CatalogAgent"

    def handle(self, task: str, context: dict | None = None) -> dict:
        task_lower = task.lower()

        if any(kw in task_lower for kw in ["reserve", "hold", "borrow"]):
            return self._reserve(context)

        if any(kw in task_lower for kw in ["available", "availability", "check"]):
            return self._check_availability(task, context)

        # Default: search
        return self._search(task)

    def _search(self, query: str) -> dict:
        results = search_books(query)
        if not results:
            return {
                "agent": self.name,
                "tool": "search_catalog",
                "message": "No matching books found in the HKUST library catalog.",
                "results": [],
            }
        # Return top 5 to keep response concise
        return {
            "agent": self.name,
            "tool": "search_catalog",
            "message": f"Found {len(results)} matching item(s) in the catalog.",
            "results": results[:5],
        }

    def _check_availability(self, task: str, context: dict | None) -> dict:
        book_id = (context or {}).get("book_id")
        if book_id:
            book = get_book(book_id)
            if book:
                return {
                    "agent": self.name,
                    "tool": "check_availability",
                    "book_id": book_id,
                    "title": book["title"],
                    "available": bool(book["available"]),
                    "copies": book["copies"],
                    "location": book["location"],
                }
        # Fall back to search
        return self._search(task)

    def _reserve(self, context: dict | None) -> dict:
        book_id = (context or {}).get("book_id", "UNKNOWN")
        return {
            "agent": self.name,
            "tool": "reserve_book",
            "message": f"Reservation request queued for book {book_id}. You will be notified via email when available.",
        }
