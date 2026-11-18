import sqlite3
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "cyber_lab.db"


def initialize_database():
    connection = sqlite3.connect(DB_NAME)

    # جدول الفحوصات (القديم)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            security_score REAL,
            risk_data TEXT,
            scan_data TEXT
        )
    """)

    # جدول المستخدمين (الجديد)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(results):
    connection = sqlite3.connect(DB_NAME)

    website = results["scan"]["url"]
    score = results["scan"]["score"]

    connection.execute("""
        INSERT INTO scans (
            website,
            scan_date,
            security_score,
            risk_data,
            scan_data
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        website,
        datetime.now().isoformat(),
        score,
        json.dumps(results["risk"], default=str),
        json.dumps(results, default=str)
    ))

    connection.commit()
    connection.close()


def get_scan_history():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    rows = connection.execute("""
        SELECT id, website, scan_date, security_score
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_statistics():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    stats = connection.execute("""
        SELECT
            COUNT(*) AS total_scans,
            ROUND(AVG(security_score), 2) AS average_score,
            SUM(CASE WHEN security_score >= 80 THEN 1 ELSE 0 END) AS safe_count,
            SUM(CASE WHEN security_score >= 50 AND security_score < 80 THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN security_score < 50 THEN 1 ELSE 0 END) AS dangerous_count
        FROM scans
    """).fetchone()

    connection.close()

    result = dict(stats)

    if result["total_scans"] is None: result["total_scans"] = 0
    if result["average_score"] is None: result["average_score"] = 0
    if result["safe_count"] is None: result["safe_count"] = 0
    if result["medium_count"] is None: result["medium_count"] = 0
    if result["dangerous_count"] is None: result["dangerous_count"] = 0

    return result


def get_scan_by_id(scan_id):
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    row = connection.execute("""
        SELECT scan_data FROM scans WHERE id = ?
    """, (scan_id,)).fetchone()

    connection.close()

    if row and row["scan_data"]:
        return json.loads(row["scan_data"])
    
    return None


# ==== دوال المستخدمين الجديدة ====

def create_user(username, password):
    connection = sqlite3.connect(DB_NAME)
    try:
        # نشفر الباسورد قبل ما نخزنه (عشان الأمان)
        hashed_pw = generate_password_hash(password)
        connection.execute("""
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """, (username, hashed_pw))
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        # هذا الخطأ يطلع إذا اسم المستخدم موجود من قبل
        return False
    finally:
        connection.close()


def get_user_by_username(username):
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row

    user = connection.execute("""
        SELECT * FROM users WHERE username = ?
    """, (username,)).fetchone()

    connection.close()

    return dict(user) if user else None


def verify_password(user, password):
    # دالة تتأكد إذا الباسورد اللي دخلته يطابق المشفر المخزون
    return check_password_hash(user["password_hash"], password)