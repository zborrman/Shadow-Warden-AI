import sqlite3


def init_pragmas(conn: sqlite3.Connection, *, foreign_keys: bool = True) -> None:
    """Apply the standard Shadow Warden SQLite pragma set to an open connection.

    Call immediately after sqlite3.connect(), before any DDL or DML.
    foreign_keys=False only for modules with known cross-DB references not yet resolved.
    """
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "PRAGMA foreign_keys=ON" if foreign_keys else "PRAGMA foreign_keys=OFF"
    )
    conn.execute("PRAGMA journal_size_limit=67108864")  # 64 MB WAL cap
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA busy_timeout=5000")            # 5-second retry on lock
