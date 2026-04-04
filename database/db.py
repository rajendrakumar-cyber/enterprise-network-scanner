import sqlite3

def init_db():
    conn = sqlite3.connect("scanner.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        result TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def save_to_db(target, result):
    conn = sqlite3.connect("scanner.db")
    c = conn.cursor()

    c.execute("INSERT INTO scans (target, result) VALUES (?, ?)", (target, result))

    conn.commit()
    conn.close()


def get_scans():
    conn = sqlite3.connect("scanner.db")
    c = conn.cursor()

    c.execute("SELECT * FROM scans ORDER BY id DESC")
    data = c.fetchall()

    conn.close()
    return data
