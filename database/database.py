import sqlite3
from werkzeug.security import generate_password_hash

# Buat database
conn = sqlite3.connect("database.db")
c = conn.cursor()

# Buat tabel users sesuai dengan app.py
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
)
""")

# Tambahkan user admin
password_hash = generate_password_hash("admin123")
c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", password_hash, "admin"))

conn.commit()
conn.close()

print("Database dan user admin berhasil dibuat!")
