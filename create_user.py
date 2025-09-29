import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "users.db"

def add_user(username, password, fullname=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    hashed_password = generate_password_hash(password)
    try:
        c.execute("INSERT INTO users (username, password, fullname) VALUES (?, ?, ?)", 
                (username, hashed_password, fullname))
        conn.commit()
        print(f"User {username} berhasil dibuat!")
    except sqlite3.IntegrityError:
        print(f"Username {username} sudah ada.")
    finally:
        conn.close()

if __name__ == "__main__":
    add_user("admin", "admin123", "Administrator")
