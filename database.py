import sqlite3
import os

DB_NAME = "scans.db"


# ----------------------------
# INIT DATABASE (SAFE FOR RENDER)
# ----------------------------
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


# ----------------------------
# SAVE SCAN RESULT
# ----------------------------
def save_scan(url, domain, score, level):
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        c = conn.cursor()

        c.execute("""
            INSERT INTO scans (url, domain, risk_score, risk_level)
            VALUES (?, ?, ?, ?)
        """, (url, domain, score, level))

        conn.commit()
        conn.close()
    except Exception as e:
        print("DB Save Error:", e)


# ----------------------------
# GET SCAN HISTORY
# ----------------------------
def get_scans():
    try:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        c = conn.cursor()

        c.execute("SELECT * FROM scans ORDER BY id DESC")
        rows = c.fetchall()

        conn.close()
        return rows
    except Exception as e:
        print("DB Read Error:", e)
        return []