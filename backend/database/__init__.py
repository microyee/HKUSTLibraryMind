"""
database/__init__.py – SQLite setup and helpers
"""
import sqlite3, json, os
from config import DATABASE_PATH
from database.seed_data import BOOKS


def get_db():
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            author      TEXT,
            year        INTEGER,
            isbn        TEXT,
            category    TEXT,
            subject     TEXT,
            location    TEXT,
            available   INTEGER,
            copies      INTEGER,
            description TEXT,
            restricted  INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'student'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reservations (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            book_id    TEXT,
            reserved_at TEXT,
            status     TEXT DEFAULT 'active'
        )
    """)
    # Seed books
    for b in BOOKS:
        cur.execute("""
            INSERT OR IGNORE INTO books
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            b["id"], b["title"], b["author"], b["year"],
            b["isbn"], b["category"],
            json.dumps(b["subject"]),
            b["location"], int(b["available"]), b["copies"],
            b["description"], int(b["restricted"])
        ))
    # Remove legacy demo accounts that are not part of the published challenge.
    cur.execute("DELETE FROM users WHERE username IN (?, ?)", ("student1", "admin"))

    # Seed the single challenge-relevant login account.
    cur.execute("INSERT OR IGNORE INTO users (username,password,role) VALUES (?,?,?)",
                ("librarian", "lib@hkust2026", "staff"))
    conn.commit()
    conn.close()


_STOP_WORDS = {
    "find", "search", "get", "show", "list", "give", "look", "looking",
    "book", "books", "about", "for", "me", "the", "a", "an", "and", "or",
    "some", "any", "can", "you", "i", "please", "help", "need", "want",
    "related", "topic", "topics", "on", "in", "of", "with", "to", "by",
    "is", "are", "does", "do", "that", "this", "these", "those", "from",
}


def search_books(query: str, category: str = None, available_only: bool = False):
    conn = get_db()
    cur = conn.cursor()

    # Split into meaningful tokens, ignoring stop words and punctuation
    raw_terms = [t.strip(".,?!;:'\"()") for t in query.lower().split()]
    terms = [t for t in raw_terms if t and t not in _STOP_WORDS and len(t) > 1]
    if not terms:
        terms = [query.lower()]  # fallback: use full query as-is

    # Each term gets an OR clause across title, author, subject, description
    conditions, params = [], []
    for term in terms:
        q = f"%{term}%"
        conditions.append(
            "(LOWER(title) LIKE ? OR LOWER(author) LIKE ?"
            " OR LOWER(subject) LIKE ? OR LOWER(description) LIKE ?)"
        )
        params.extend([q, q, q, q])

    sql = f"""
        SELECT * FROM books
        WHERE restricted = 0
          AND ({' OR '.join(conditions)})
    """
    if category:
        sql += " AND category = ?"
        params.append(category)
    if available_only:
        sql += " AND available = 1"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_book(book_id: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM books WHERE id = ? AND restricted = 0", (book_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_categories():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT category FROM books WHERE restricted = 0 ORDER BY category")
    cats = [r[0] for r in cur.fetchall()]
    conn.close()
    return cats
