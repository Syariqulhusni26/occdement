from librouteros import connect

API_HOST = "192.168.88.1"   # ganti dengan IP router Mikrotik
API_USER = "admin"          # username Mikrotik
API_PASS = "password"       # password Mikrotik

def disable_device(ip):
    """Tambah IP ke address-list blocked"""
    api = connect(username=API_USER, password=API_PASS, host=API_HOST)
    api.path("ip", "firewall", "address-list").add(address=ip, list="blocked")
    print(f"[MikroTik] Device {ip} berhasil di-disable")

def enable_device(ip):
    """Hapus IP dari address-list blocked"""
    api = connect(username=API_USER, password=API_PASS, host=API_HOST)
    for addr in api.path("ip", "firewall", "address-list").select():
        if addr.get("address") == ip and addr.get("list") == "blocked":
            api.path("ip", "firewall", "address-list").remove(addr[".id"])
            print(f"[MikroTik] Device {ip} berhasil di-enable")
