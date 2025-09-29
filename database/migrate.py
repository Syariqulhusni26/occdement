import sqlite3

conn = sqlite3.connect("database.db")
c = conn.cursor()

# Tambah kolom role
try:
    c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    print("Kolom 'role' berhasil ditambahkan.")
except sqlite3.OperationalError:
    print("Kolom 'role' sudah ada, dilewati.")

# Tambah kolom created_at
try:
    c.execute("ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT (datetime('now'))")
    print("Kolom 'created_at' berhasil ditambahkan.")
except sqlite3.OperationalError:
    print("Kolom 'created_at' sudah ada, dilewati.")

conn.commit()
conn.close()
print("Migrasi selesai!")
