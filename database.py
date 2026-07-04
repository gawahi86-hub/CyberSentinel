import sqlite3

DB_NAME = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            risk_level TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(url, domain, score, level):
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    c = conn.cursor()

    c.execute("""
        INSERT INTO scans (url, domain, risk_score, risk_level)
        VALUES (?, ?, ?, ?)
    """, (url, domain, score, level))

    conn.commit()
    conn.close()


def get_scans():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT * FROM scans ORDER BY id DESC")
    rows = c.fetchall()

    conn.close()
    return rows