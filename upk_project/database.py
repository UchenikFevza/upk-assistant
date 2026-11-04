import sqlite3
import hashlib
import uuid
from datetime import datetime

DB_FILE = "college.db"

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        login TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'operator',
        password_hash TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        building TEXT NOT NULL,
        floor INTEGER NOT NULL,
        room TEXT NOT NULL,
        zone_name TEXT,
        qr_key TEXT UNIQUE NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        public_number TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        location_id INTEGER,
        status TEXT NOT NULL DEFAULT 'Новая',
        assignee_name TEXT,
        tracking_token TEXT UNIQUE NOT NULL,
        is_dangerous INTEGER DEFAULT 0,
        student_name TEXT,
        student_card TEXT,
        photo_url TEXT,
        admin_reply TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (location_id) REFERENCES locations (id)
    );
    """)

    # Авто-миграция колонок для уже созданной БД
    cursor.execute("PRAGMA table_info(tickets)")
    columns = [col[1] for col in cursor.fetchall()]
    if "student_name" not in columns:
        cursor.execute("ALTER TABLE tickets ADD COLUMN student_name TEXT")
    if "student_card" not in columns:
        cursor.execute("ALTER TABLE tickets ADD COLUMN student_card TEXT")
    if "photo_url" not in columns:
        cursor.execute("ALTER TABLE tickets ADD COLUMN photo_url TEXT")
    if "admin_reply" not in columns:
        cursor.execute("ALTER TABLE tickets ADD COLUMN admin_reply TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT NOT NULL,
        actor_name TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (ticket_id) REFERENCES tickets (id)
    );
    """)

    cursor.execute("SELECT id FROM users WHERE login = 'admin'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO users (name, login, role, password_hash)
        VALUES (?, ?, ?, ?)
        """, ("Инженер УПК", "admin", "admin", hash_password("admin123")))

    conn.commit()
    conn.close()

def create_ticket(title: str, description: str, category: str, location_id: int | None = None, 
                  is_dangerous: bool = False, student_name: str | None = None, 
                  student_card: str | None = None, photo_url: str | None = None) -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("SELECT count(id) FROM tickets")
    count = cursor.fetchone()[0]
    public_number = f"ТИК-{1001 + count}"
    tracking_token = str(uuid.uuid4())[:8]

    cursor.execute("""
    INSERT INTO tickets (public_number, title, description, category, location_id, status, tracking_token, 
                         is_dangerous, student_name, student_card, photo_url, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'Новая', ?, ?, ?, ?, ?, ?, ?)
    """, (public_number, title, description, category, location_id, tracking_token, 
          1 if is_dangerous else 0, student_name, student_card, photo_url, now, now))
    
    ticket_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO ticket_history (ticket_id, old_status, new_status, actor_name, note, created_at)
    VALUES (?, NULL, 'Новая', 'Система', 'Заявка зарегистрирована', ?)
    """, (ticket_id, now))

    conn.commit()
    conn.close()

    return {
        "id": ticket_id,
        "public_number": public_number,
        "tracking_token": tracking_token,
        "status": "Новая"
    }

def get_student_tickets(student_card: str) -> list[dict]:
    conn = get_connection()
    tickets = conn.execute("""
        SELECT * FROM tickets WHERE student_card = ? ORDER BY id DESC
    """, (student_card,)).fetchall()
    conn.close()
    return [dict(t) for t in tickets]

def save_admin_reply(ticket_id: int, reply_text: str, new_status: str, actor_name: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM tickets WHERE id = ?", (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        conn.close()
        return False

    old_status = ticket["status"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE tickets 
        SET admin_reply = ?, status = ?, assignee_name = ?, updated_at = ?
        WHERE id = ?
    """, (reply_text, new_status, actor_name, now, ticket_id))

    cursor.execute("""
        INSERT INTO ticket_history (ticket_id, old_status, new_status, actor_name, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ticket_id, old_status, new_status, actor_name, f"Ответ специалиста: {reply_text[:50]}...", now))

    conn.commit()
    conn.close()
    return True