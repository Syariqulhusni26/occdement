from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from routeros_api import RouterOsApiPool
import routeros_api
import requests
import sqlite3
import secrets
import string
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = "rahasia123"

# Status global
status = {"ip_enabled": True}

# List sementara untuk menyimpan data perangkat manual
devices = []

# Bikin list global untuk menyimpan jadwal
schedules = []
scheduler = BackgroundScheduler()
scheduler.start()

# ================= KONEKSI DATABASE =================
DB_PATH = "database/database.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row  # biar bisa diakses kayak dict
    return db

# ================= LOGIN =================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validasi input
        if not username or not password:
            flash("Username dan password wajib diisi!", "danger")
            return redirect(url_for("signup"))

        db = get_db()
        hashed_pw = generate_password_hash(password)

        try:
            # Insert user baru
            db.execute(
                """
                INSERT INTO users (username, password, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, hashed_pw, "user", datetime.now())
            )
            db.commit()

            flash("Akun berhasil dibuat, silakan login.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username sudah dipakai, silakan pilih yang lain.", "danger")
            return redirect(url_for("signup"))

    # GET request → render halaman signup
    return render_template("signup.html", title="Signup")


@app.route("/users")
@login_required
def users_page():
    db = get_db()
    cur = db.execute("SELECT id, username, password, role, created_at FROM users ORDER BY created_at DESC")

    users = cur.fetchall()

    return render_template(
        "users.html",
        title="Users",
        users=users,
        current_role=session.get("role")  # kirim role ke template
    )

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    db = get_db()
    # hanya admin yang boleh hapus
    cur = db.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
    current_role = cur.fetchone()
    if current_role["role"] != "admin":
        flash("Akses ditolak. Hanya admin yang boleh hapus user.", "danger")
        return redirect(url_for("users_page"))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash("User berhasil dihapus.", "success")
    return redirect(url_for("users_page"))


@app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    db = get_db()

    # hanya admin yang boleh edit
    cur = db.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
    current_role = cur.fetchone()
    if current_role["role"] != "admin":
        flash("Akses ditolak. Hanya admin yang boleh edit user.", "danger")
        return redirect(url_for("users_page"))

    if request.method == "POST":
        role = request.form.get("role")
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()
        flash("User berhasil diperbarui.", "success")
        return redirect(url_for("users_page"))

    # ambil data user yg mau diedit
    cur = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    return render_template("edit_user.html", user=user, title="Edit User")

import secrets
import string

@app.route("/reset_password/<int:user_id>", methods=["POST"])
@login_required
def reset_password(user_id):
    # cek apakah yang login admin
    if session.get("role") != "admin":
        flash("Anda tidak punya hak untuk reset password!", "danger")
        return redirect(url_for("users_page"))

    # generate password random
    alphabet = string.ascii_letters + string.digits
    new_password = ''.join(secrets.choice(alphabet) for i in range(10))

    hashed_pw = generate_password_hash(new_password)

    db = get_db()
    db.execute("UPDATE users SET password=? WHERE id=?", (hashed_pw, user_id))
    db.commit()

    flash(f"Password baru untuk user ID {user_id} adalah: {new_password}", "info")
    return redirect(url_for("users_page"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username dan password wajib diisi!", "danger")
            return redirect(url_for("login"))

        # ambil koneksi db
        db = get_db()
        user = db.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()  # clear session lama
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]  # simpan role

            flash(f"Selamat datang, {user['username']}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Username atau password salah!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", title="Login")


@app.route("/logout")
def logout():
    session.clear()
    flash("Anda telah logout.", "success")
    return redirect(url_for("login"))

#

# ================= ROUTE LOGIN SNIPE-IT =================
@app.route("/snipeit/login", methods=["GET", "POST"])
def snipeit_login():
    if request.method == "POST":
        url = request.form.get("url")
        token = request.form.get("token")

        # cek koneksi ke Snipe-IT
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        try:
            resp = requests.get(f"{url}/accessories", headers=headers, timeout=5)
            if resp.status_code == 200:
                session["SNIPEIT_URL"] = url
                session["SNIPEIT_TOKEN"] = token
                flash("Login ke Snipe-IT berhasil!", "success")
                return redirect(url_for("accessories"))
            else:
                flash("Gagal login ke Snipe-IT. Periksa URL atau Token.", "danger")
        except Exception as e:
            flash(f"Error koneksi: {e}", "danger")

    return render_template("snipeit_login.html", title="Login Snipe-IT")

SNIPEIT_URL = None
SNIPEIT_TOKEN = None

def get_snipeit_headers():
    url = session.get("SNIPEIT_URL")
    token = session.get("SNIPEIT_TOKEN")
    if not url or not token:
        raise Exception("Belum login Snipe-IT")
    return url, {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }


# 🔹 Ambil data peminjam langsung dari SnipeIT
def get_borrowers_from_snipeit():
    headers = {
        "Authorization": f"Bearer {SNIPEIT_TOKEN}",
        "Accept": "application/json"
    }
    url = f"{SNIPEIT_URL}/accessories/1/checkout"  
    # ⬆️ ganti "1" sesuai ID accessories HHT

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            "header": [["Image","Checked out to","Notes","Checkout Date","Actions"]],
            "data": []
        }
        
# 🔹 JSON route
@app.route("/borrowers/json")
def borrowers_json():
    data = get_borrowers_from_snipeit()
    return jsonify(data)

# 🔹 HTML route
@app.route("/borrowers")
def borrowers_html():
    data = get_borrowers_from_snipeit()
    return render_template("borrowers.html", data=data)

# ================= ROUTES SNIPE-IT =================
@app.route("/accessories")
@login_required
def accessories():
    try:
        url, headers = get_snipeit_headers()
    except Exception:
        flash("Silakan login ke Snipe-IT dulu", "warning")
        return redirect(url_for("snipeit_login"))

    resp = requests.get(f"{url}/accessories", headers=headers)
    accessories = resp.json().get("rows", []) if resp.status_code == 200 else []

    for acc in accessories:
        acc_id = acc["id"]
        borrowers_url = f"{url}/accessories/{acc_id}/checkedout"
        b_resp = requests.get(borrowers_url, headers=headers)
        acc["borrowers"] = b_resp.json().get("rows", []) if b_resp.status_code == 200 else []

    return render_template("accessories.html", accessories=accessories, title="Accessories")


@app.route("/checkout/<int:accessory_id>/<int:user_id>", methods=["POST"])
def checkout_accessory(accessory_id, user_id):
    headers = {
        "Authorization": f"Bearer {SNIPEIT_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {
        "assigned_to": user_id,
        "checkout_to_type": "user",
        "note": "Dipinjam lewat sistem custom"
    }
    try:
        response = requests.post(
            f"{SNIPEIT_URL}/accessories/{accessory_id}/checkout",
            headers=headers,
            json=payload
        )
        if response.status_code == 200:
            flash("Accessories berhasil dipinjam dan stok di SnipeIT berkurang ✅", "success")
        else:
            flash(f"Gagal checkout accessories (status {response.status_code}): {response.text}", "danger")
    except Exception as e:
        flash(f"Error koneksi ke SnipeIT: {str(e)}", "danger")
    return redirect(url_for("accessories"))

# # ================= KONEKSI MIKROTIK =================
# try:
#     connection = routeros_api.RouterOsApiPool(
#         #host='192.168.45.1',  # IP Mikrotik
#         host='192.168.55.1',  # IP Mikrotik
#         username='admin',     # username mikrotik
#         password='1',          # password mikrotik
#         port=8728,            # port API default
#         plaintext_login=True
#     )
#     api = connection.get_api()
# except Exception as e:
#     print("Gagal koneksi ke Mikrotik:", e)
#     api = None

# ================= KONEKSI MIKROTIK (wrapper baru) =================
def get_mikrotik_api():
    host = session.get("mt_host")
    username = session.get("mt_username")
    password = session.get("mt_password")

    if not host or not username or not password:
        return None

    try:
        api_pool = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=8728,
            plaintext_login=True
        )
        return api_pool.get_api()
    except Exception as e:
        print("Gagal koneksi ke MikroTik:", e)
        return None

# variabel global untuk kompatibilitas
api = None

@app.route("/mikrotik_login", methods=["GET", "POST"])
@login_required
def mikrotik_login():
    if request.method == "POST":
        host = request.form.get("host")
        username = request.form.get("username")
        password = request.form.get("password")

        try:
            api_pool = routeros_api.RouterOsApiPool(
                host, username=username, password=password, plaintext_login=True
            )
            api = api_pool.get_api()

            # Simpan ke session
            session["mt_host"] = host
            session["mt_username"] = username
            session["mt_password"] = password

            flash("Login MikroTik berhasil!", "success")
            return redirect(url_for("firewall_address"))

        except Exception as e:
            app.logger.exception("Gagal login MikroTik:")
            flash(f"Gagal login MikroTik: {e}", "danger")
            return redirect(url_for("mikrotik_login"))

    return render_template("mikrotik_login.html", title="Login MikroTik")

@app.route("/mikrotik_logout")
@login_required
def mikrotik_logout():
    session.pop("mt_host", None)
    session.pop("mt_username", None)
    session.pop("mt_password", None)
    flash("Logout MikroTik berhasil.", "info")
    return redirect(url_for("mikrotik_login"))


# ================= WEB ROUTES =================
@app.route("/")
@login_required
def index():
    """Tampilkan daftar device manual + device dari ARP MikroTik"""
    arp_devices = []
    address_list = []
    api = get_mikrotik_api()

    if api:
        try:
            # --- Ambil ARP table semua interface ---
            arp_entries = api.get_resource("/ip/arp").get()

            # --- Ambil semua IP di BLOCKED list ---
            blocked_ips = api.get_resource("/ip/firewall/address-list").get(list="BLOCKED")
            blocked_set = {item.get("address") for item in blocked_ips if item.get("address")}

            print("DEBUG - BLOCKED SET:", blocked_set)

            for dev in arp_entries:
                ip = dev.get("address")
                mac = dev.get("mac-address")
                if ip and ip.startswith("192.168.55."):
                    arp_devices.append({
                        "ip": ip,
                        "name": mac,
                        "enabled": ip not in blocked_set
                    })

            # --- Ambil data address-list dengan detail (biar .id ikut) ---
            addr_list_res = api.get_resource("/ip/firewall/address-list").call("print")

            for i, entry in enumerate(addr_list_res):
                # ambil .id asli dari Mikrotik
                mikrotik_id = entry.get('.id')
                if isinstance(mikrotik_id, dict):
                    entry_id = mikrotik_id.get('id')  # fallback ambil 'id' saja
                else:
                    entry_id = mikrotik_id

                addr = entry.get("address")
                lst = entry.get("list")
                comment = entry.get("comment", "")

                address_list.append({
                    "id": entry_id,  # <-- Hanya ID Mikrotik
                    "address": addr,
                    "list": lst,
                    "comment": comment
                })

                print(f"DEBUG Entry {i} | .id={entry_id} | Address={addr} | List={lst} | Comment={comment}")

        except Exception as e:
            print("Gagal ambil ARP atau address-list:", e)

    return render_template(
        "arp_device.html",
        devices=devices,
        arp_devices=arp_devices,
        schedules=schedules,
        address_list=address_list,
        title="Perangkat ARP Terdeteksi"
    )
    
@app.route("/home")
@login_required
def home():
    """Tampilkan daftar device manual + device dari ARP MikroTik"""
    arp_devices = []
    address_list = []
    api = get_mikrotik_api()
    db = get_db()
    cur = db.execute("SELECT * FROM history ORDER BY date DESC")
    histories = cur.fetchall()
    
    # mengambil jumlah user
    cur = db.execute("SELECT COUNT(*) AS cnt FROM users")
    row = cur.fetchone()
    user_count = row['cnt'] if row else 0

    if api:
        try:
            # --- Ambil ARP table semua interface ---
            arp_entries = api.get_resource("/ip/arp").get()

            # --- Ambil semua IP di BLOCKED list ---
            blocked_ips = api.get_resource("/ip/firewall/address-list").get(list="BLOCKED")
            blocked_set = {item.get("address") for item in blocked_ips if item.get("address")}

            print("DEBUG - BLOCKED SET:", blocked_set)

            for dev in arp_entries:
                ip = dev.get("address")
                mac = dev.get("mac-address")
                if ip and ip.startswith("192.168.55."):
                    arp_devices.append({
                        "ip": ip,
                        "name": mac,
                        "enabled": ip not in blocked_set
                    })

            # --- Ambil data address-list dengan detail (biar .id ikut) ---
            addr_list_res = api.get_resource("/ip/firewall/address-list").call("print")

            for i, entry in enumerate(addr_list_res):
                # ambil .id asli dari Mikrotik
                mikrotik_id = entry.get('.id')
                if isinstance(mikrotik_id, dict):
                    entry_id = mikrotik_id.get('id')  # fallback ambil 'id' saja
                else:
                    entry_id = mikrotik_id

                addr = entry.get("address")
                lst = entry.get("list")
                comment = entry.get("comment", "")

                address_list.append({
                    "id": entry_id,  # <-- Hanya ID Mikrotik
                    "address": addr,
                    "list": lst,
                    "comment": comment
                })

                print(f"DEBUG Entry {i} | .id={entry_id} | Address={addr} | List={lst} | Comment={comment}")

        except Exception as e:
            print("Gagal ambil ARP atau address-list:", e)

    return render_template(
        "index.html",
        devices=devices,
        arp_devices=arp_devices,
        schedules=schedules,
        address_list=address_list,
        histories=histories,
        user_count=user_count,
        title="Dashboard"
    )

@app.route("/firewall_address")
@login_required
def firewall_address():
    """Tampilkan daftar device manual + device dari ARP MikroTik"""
    arp_devices = []
    address_list = []
    devices = []     # <-- sementara kosong, bisa diisi dari DB kalau ada
    schedules = []   # <-- sementara kosong
    api = get_mikrotik_api()

    try:
        api = get_mikrotik_api()
    except Exception as e:
        flash(f"{e} : Silahkan Login Dahulu !", "danger")
        return redirect(url_for("mikrotik_login"))

    try:
        # --- Ambil ARP table semua interface ---
        arp_entries = api.get_resource("/ip/arp").get()

        # --- Ambil semua IP di BLOCKED list ---
        blocked_ips = api.get_resource("/ip/firewall/address-list").get(list="BLOCKED")
        blocked_set = {item.get("address") for item in blocked_ips if item.get("address")}

        print("DEBUG - BLOCKED SET:", blocked_set)

        for dev in arp_entries:
            ip = dev.get("address")
            mac = dev.get("mac-address")
            if ip and ip.startswith("192.168.55."):
                arp_devices.append({
                    "ip": ip,
                    "name": mac,
                    "enabled": ip not in blocked_set
                })

        # --- Ambil data address-list dengan detail (biar .id ikut) ---
        addr_list_res = api.get_resource("/ip/firewall/address-list").call("print")

        for i, entry in enumerate(addr_list_res):
            # ambil .id asli dari Mikrotik
            mikrotik_id = entry.get('.id')
            if isinstance(mikrotik_id, dict):
                entry_id = mikrotik_id.get('id')  # fallback ambil 'id' saja
            else:
                entry_id = mikrotik_id

            addr = entry.get("address")
            lst = entry.get("list")
            comment = entry.get("comment", "")

            address_list.append({
                "id": entry_id,  # <-- ID Mikrotik asli
                "address": addr,
                "list": lst,
                "comment": comment
            })

            print(f"DEBUG Entry {i} | .id={entry_id} | Address={addr} | List={lst} | Comment={comment}")

    except Exception as e:
        print("Gagal ambil ARP atau address-list:", e)
        flash(f"Gagal ambil data dari MikroTik: {e}", "danger")

    return render_template(
        "firewall_address.html",
        devices=devices,
        arp_devices=arp_devices,
        schedules=schedules,
        address_list=address_list,
        title="Firewall Address List"
    )

@app.route('/consumables')
@login_required
def consumables():
    try:
        url, headers = get_snipeit_headers()
    except Exception:
        flash("Silakan login ke Snipe-IT dulu", "warning")
        return redirect(url_for("snipeit_login"))

    try:
        resp = requests.get(f"{url}/consumables", headers=headers)
        consumables = resp.json().get("rows", []) if resp.status_code == 200 else []

        if resp.status_code == 200:
            return render_template("consumables.html", consumables=consumables, title="Consumables")
        else:
            flash(f"Gagal mengambil data Consumables (status {resp.status_code})", "danger")
            return render_template("consumables.html", consumables=[], title="Consumables")
    except Exception as e:
        flash(f"Error koneksi ke Snipe-IT: {e}", "danger")
        return render_template("consumables.html", consumables=[], title="Consumables")


# helper: ambil id fleksibel dari entry routeros
def extract_id(entry: dict):
    """Return id string from routeros_api entry (tries .id then id)."""
    return entry.get('.id') or entry.get('id') or entry.get('.id')

@app.route("/history")
@login_required
def history_page():
    db = get_db()
    cur = db.execute("SELECT * FROM history ORDER BY date DESC")
    histories = cur.fetchall()
    return render_template("index.html", histories=histories)

def save_history(ip, user, source, status, action):
    """Helper untuk simpan history ke SQLite"""
    db = get_db()
    db.execute(
        "INSERT INTO history (ip, user, source, status, action, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (ip, user, source, status, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.commit()

@app.route("/history/delete/<int:history_id>", methods=["POST"])
@login_required
def delete_history(history_id):
    db = get_db()
    db.execute("DELETE FROM history WHERE id = ?", (history_id,))
    db.commit()
    flash("Data history berhasil dihapus.", "success")
    return redirect(url_for("home"))

@app.route("/history/clear", methods=["POST"])
@login_required
def clear_history():
    db = get_db()
    db.execute("DELETE FROM history")
    db.commit()
    flash("Semua history berhasil dibersihkan.", "success")
    return redirect(url_for("home"))

@app.route("/toggle/<ip>")
def toggle_device(ip):
    global devices
    api = get_mikrotik_api()
    
    if not api:
        flash("Tidak terkoneksi ke MikroTik!", "danger")
        return redirect(url_for("index"))

    addr_list = api.get_resource("/ip/firewall/address-list")
    filter_rules = api.get_resource("/ip/firewall/filter")

    # --- cek device manual dulu (lokal) ---
    device = next((d for d in devices if d["ip"] == ip), None)
    if device:
        device["enabled"] = not device["enabled"]
        status_text = "diaktifkan" if device["enabled"] else "dinonaktifkan"
        flash(f"Perangkat {device['name']} ({ip}) berhasil {status_text}!", "warning")
        return redirect(url_for("index"))

    try:
        # ambil entri address-list BLOCKED untuk ip ini (kalau ada)
        blocked_entries = addr_list.get(address=ip, list="BLOCKED")
        
    except Exception as e:
        blocked_entries = []
        app.logger.exception("Gagal mengambil address-list: %s", e)
        flash("Gagal mengambil address-list dari MikroTik.", "danger")
        return redirect(url_for("index"))

    # kalau ada di address-list -> berarti sekarang kita 'enable' (hapus dari blocked)
    if blocked_entries:
        try:
            # hapus semua entri BLOCKED yang cocok (biasanya 1)
            for be in blocked_entries:
                be_id = extract_id(be)
                if be_id:
                    addr_list.remove(id=be_id)
                    app.logger.debug("Removed address-list id=%s for %s", be_id, ip)
                else:
                    app.logger.warning("Tidak menemukan ID pada address-list entry: %s", be)

            # hapus juga semua firewall filter rules yang khusus memblokir IP ini (chain=forward, src-address=ip, action=drop)
            ip_rules = filter_rules.get(chain="forward", src_address=ip, action="drop")
            for r in ip_rules:
                rid = extract_id(r)
                if rid:
                    filter_rules.remove(id=rid)
                    app.logger.debug("Removed firewall rule id=%s for %s", rid, ip)
                else:
                    app.logger.warning("Tidak menemukan ID pada firewall rule entry: %s", r)

            flash(f"IP {ip} diaktifkan (dihapus dari BLOCKED dan firewall filter).", "success")
            
            # ✅ Simpan history
            save_history(ip, session.get("username"), "ARP Devices", "ALLOWED", f"Enable {ip}")
            
        except Exception as e:
            app.logger.exception("Gagal menghapus entri: %s", e)
            flash(f"Gagal mengaktifkan IP {ip}: {e}", "danger")
        return redirect(url_for("index"))

    # kalau tidak ada di address-list -> berarti kita 'disable' (tambahkan ke blocked + buat rule drop)
    try:
        # tambahkan ke address-list BLOCKED (jika belum ada)
        addr_list.add(address=ip, list="BLOCKED", comment="Disabled via web interface")
        app.logger.debug("Added %s to address-list BLOCKED", ip)
    except Exception as e:
        # kadang add bisa fail jika sudah ada; kita log tetapi lanjut mencoba membuat rule
        app.logger.exception("Gagal menambahkan address-list: %s", e)

    try:
        # cek apakah sudah ada rule filter spesifik untuk IP ini
        existing_rules = filter_rules.get(chain="forward", src_address=ip, action="drop")
        if existing_rules:
            app.logger.debug("Rule drop untuk %s sudah ada (tidak ditambah lagi).", ip)
        else:
            # buat rule drop spesifik untuk IP ini
            filter_rules.add(chain="forward", src_address=ip, action="drop", comment=f"Block {ip} via web")
            app.logger.debug("Menambahkan firewall rule drop untuk %s", ip)
        flash(f"IP {ip} dinonaktifkan (ditambahkan ke BLOCKED dan firewall rule).", "danger")
        
        # ✅ Simpan history
        save_history(ip, session.get("username"), "ARP Devices", "BLOCKED", f"Disable {ip}")
        
    except Exception as e:
        app.logger.exception("Gagal menambahkan rule firewall: %s", e)
        flash(f"Gagal memblokir IP {ip}: {e}", "danger")

    return redirect(url_for("index"))

# ================= ADDRESS LIST =================

@app.route("/address/add", methods=["POST"])
def address_list_add():
    api = get_mikrotik_api()
    
    if api is None:
        flash("Mikrotik tidak terkoneksi", "danger")
        return redirect(url_for("index"))

    ip = request.form.get("ip", "").strip()
    category = request.form.get("category", "BLOCKED").strip()  # mis: BLOCKED / ALLOWED
    comment = request.form.get("comment", "").strip()

    if not ip:
        flash("Isi IP terlebih dahulu.", "warning")
        return redirect(url_for("index"))

    try:
        addr_list = api.get_resource("/ip/firewall/address-list")
        filter_rules = api.get_resource("/ip/firewall/filter")

        # Tambahkan ke address-list
        addr_list.add(address=ip, list=category, comment=comment)

        # Kalau BLOCKED → auto tambahkan rule drop
        if category.upper() == "BLOCKED":
            existing = filter_rules.get(chain="forward", src_address=ip, action="drop")
            if not existing:
                filter_rules.add(
                    chain="forward",
                    src_address=ip,
                    action="drop",
                    comment=f"Block {ip} via web (auto add)"
                )

        # Kalau ALLOWED → pastikan rule drop tidak ada
        elif category.upper() == "ALLOWED":
            rules = filter_rules.get(chain="forward", src_address=ip, action="drop")
            for r in rules:
                rid = r.get(".id")
                if rid:
                    filter_rules.remove(id=rid)

        flash(f"IP {ip} berhasil ditambahkan ke list '{category}'.", "success")

    except Exception as e:
        app.logger.exception("Gagal menambahkan address-list:")
        flash(f"Gagal menambahkan IP: {e}", "danger")

    return redirect(url_for("firewall_address"))


@app.route("/address/toggle", methods=["POST"])
def toggle_address_fallback():
    api = get_mikrotik_api()
    
    if not api:
        flash("Mikrotik tidak terkoneksi!", "danger")
        return redirect(url_for("index"))

    entry_id = request.form.get("entry_id")
    address = request.form.get("address")
    lst = request.form.get("list")

    try:
        addr_list = api.get_resource("/ip/firewall/address-list")
        filter_rules = api.get_resource("/ip/firewall/filter")

        entries = addr_list.get(address=address, list=lst)
        if not entries:
            flash("Entry tidak ditemukan!", "danger")
            return redirect(url_for("index"))

        entry = entries[0]
        entry_id = entry.get(".id") or entry.get("id")
        ip = entry.get("address")
        cur_list = entry.get("list", "").upper()
        new_list = "ALLOWED" if cur_list == "BLOCKED" else "BLOCKED"

        addr_list.set(id=entry_id, list=new_list, comment=entry.get("comment", ""))

        if new_list == "ALLOWED":
            rules = filter_rules.get(chain="forward", src_address=ip, action="drop")
            for r in rules:
                rid = r.get(".id") or r.get("id")
                if rid:
                    filter_rules.remove(id=rid)
        else:
            existing = filter_rules.get(chain="forward", src_address=ip, action="drop")
            if not existing:
                filter_rules.add(chain="forward", src_address=ip, action="drop", comment=f"Block {ip} via web")

        flash(f"IP {ip} dipindah dari {cur_list} → {new_list}.", "success")

        # ✅ Simpan history
        save_history(ip, session.get("username"), "Firewall Address List", new_list, f"Moved {ip} to {new_list}")

    except Exception as e:
        flash(f"Gagal toggle entry: {e}", "danger")

    return redirect(url_for("firewall_address"))


@app.route("/address/delete", methods=["POST"])
def delete_address_fallback():
    """Hapus entry dari address-list + sinkronisasi firewall"""
    if not api:
        flash("Mikrotik tidak terkoneksi!", "danger")
        return redirect(url_for("index"))

    entry_id = request.form.get("entry_id")
    address = request.form.get("address")
    lst = request.form.get("list")
    
    if entry_id and not entry_id.startswith("*"):
        entry_id = None

    try:
        addr_list = api.get_resource("/ip/firewall/address-list")
        filter_rules = api.get_resource("/ip/firewall/filter")
        
        entries = addr_list.get()
        for e in entries:
            print(e)  # cek apakah key-nya '.id' atau 'id'

        if entry_id:
            # hapus berdasarkan ID
            addr_list.remove(id=entry_id)
        else:
            # fallback cari dulu id-nya
            entries = addr_list.get(address=address, list=lst)
            for e in entries:
                eid = e.get("id") or e.get(".id")
                if eid:
                    addr_list.remove(**{".id": eid})

        # juga hapus firewall rule yang match IP ini
        rules = filter_rules.get(chain="forward", src_address=address, action="drop")
        for r in rules:
            rid = r.get("id") or r.get(".id")
            if rid:
                filter_rules.remove(id=rid)

        flash(f"Entry {address} berhasil dihapus.", "success")

    except Exception as e:
        app.logger.exception("Gagal hapus address-list:")
        flash(f"Gagal menghapus entry: {e}", "danger")

    return redirect(url_for("firewall_address"))



# ================= FIREWALL FILTER API ENDPOINT =================
@app.route('/api/firewall/filter/<action>', methods=['POST'])
def manage_firewall_filter(action):
    """Endpoint API untuk mengelola firewall filter"""
    api = get_mikrotik_api()
    
    if not api:
        return jsonify({'error': 'Tidak terkoneksi ke MikroTik'}), 500
        
    data = request.get_json()
    ip_address = data.get('ip')
        
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    try:
        filter_rules = api.get_resource("/ip/firewall/filter")
        
        if action == 'disable':
            # Cari rule yang ada untuk IP ini
            existing_rule = filter_rules.get(src_address=ip_address, chain="input", action="drop")
            
            if existing_rule:
                return jsonify({'message': f'Rule untuk {ip_address} sudah ada'}), 200
            
            # Tambahkan rule baru
            response = filter_rules.add(
                chain="input",
                src_address=ip_address,
                action="drop",
                comment=f"Blocked via API"
            )
            return jsonify(response.json()), 201
            
        elif action == 'enable':
            # Hapus rule untuk IP ini
            existing_rule = filter_rules.get(src_address=ip_address, chain="input", action="drop")
            
            if not existing_rule:
                return jsonify({'message': f'Tidak ada rule untuk {ip_address}'}), 404
            
            # Hapus rule
            rule_id = existing_rule[0].get('.id')
            if rule_id:
                filter_rules.remove(id=rule_id)
                return jsonify({'message': f'Rule untuk {ip_address} dihapus'}), 200
            else:
                return jsonify({'error': 'ID rule tidak ditemukan'}), 500
                
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ================= HELPER =================
def is_blocked(ip):
    """Cek apakah IP masuk ke address-list BLOCKED"""
    api = get_mikrotik_api()
    
    if not api:
        return False
    addr_list = api.get_resource("/ip/firewall/address-list")
    existing = addr_list.get(address=ip, list="BLOCKED")
    return len(existing) > 0

# ================= API ROUTES =================
@app.route("/api/networks", methods=["GET"])
def networks():
    api = get_mikrotik_api()
    
    if not api:
        app.logger.error("API tidak Terkoneksi ke Mikrotik")
        return jsonify({"error": "Tidak terkoneksi ke Mikrotik"}), 500
    
    ip_addr = api.get_resource("/ip/address")
    networks = ip_addr.get(interface="ether1")
    arp = api.get_resource("/ip/arp")
    arp_list = arp.get(interface="ether1")
    
    filtered_arp = []
    for entry in arp_list:
        ip = entry.get("address")
        if ip and ip.startswith("192.168.55."):
            filtered_arp.append(entry)
    
    return jsonify({
        "ip_networks": networks,
        "arp_table": filtered_arp
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)




# from flask import Flask, render_template, redirect, url_for
# from services.mikrotik_service import disable_device, enable_device

# app = Flask(__name__)

# @app.route("/")
# def dashboard():
#     # Ini Data Dummy sementara
#     assets = [
#     {"name": "VMT-01", "serial": "ABC123", "status": "Dipinjam", "ip": "192.168.1.10"},
#     {"name": "VMT-02", "serial": "XYZ456", "status": "Tersedia", "ip": "192.168.1.11"}, 
#     ]

#     return render_template("dashboard.html", assets=assets)

# @app.route("/disable/<ip>")
# def disable(ip):
#     disable_device(ip)
#     return redirect(url_for("dashboard"))

# @app.route("/enable/<ip>")
# def enable(ip):
#     enable_device(ip)
#     return redirect(url_for("dashboard"))

# if __name__ == "__main__":
#     app.run(debug=True)