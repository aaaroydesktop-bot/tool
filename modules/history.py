import sqlite3
import datetime

DB = "database/toolkit.db"


def init_db():

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            target TEXT,
            time TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def save_history(action, target):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        "INSERT INTO history(action,target,time) VALUES(?,?,?)",
        (
            action,
            target,
            str(datetime.datetime.now())
        )
    )

    conn.commit()
    conn.close()


def show_history():

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM history ORDER BY id DESC LIMIT 20"
    )

    rows = cur.fetchall()

    for row in rows:

        print(row)

    conn.close()