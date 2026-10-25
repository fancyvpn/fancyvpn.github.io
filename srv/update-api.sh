#!/bin/bash
# Fancy VPN — обновление сервера регистрации на уже работающем сервере. Секретов не содержит.
set -e
cp /opt/fancyvpn/api.py /opt/fancyvpn/api.py.bak
cat > /opt/fancyvpn/api.py <<'PYEOF'
#!/usr/bin/env python3
"""
Fancy VPN — сервер регистрации устройств.

Приложение отправляет сюда публичный ключ WireGuard своего устройства,
сервер добавляет его в WireGuard и возвращает внутренний IP-адрес.
Работает только на стандартной библиотеке Python, без зависимостей.

  POST /v1/register   {"public_key": "..."}   заголовок X-App-Token
  POST /v1/trial      {"device": "<sha256 hex>"} заголовок X-App-Token
       -> {"first_seen": unix, "now": unix} — когда устройство впервые открыло приложение
          (для 10 дней без рекламы). Храним только хеш, сам Android ID на сервер не попадает.
  GET  /v1/health
  GET  /v1/info       {"public_key": "..."} — публичный ключ WireGuard этого сервера
"""
import base64
import hmac
import ipaddress
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("FANCY_PORT", "8080"))
DB_PATH = os.environ.get("FANCY_DB", "/var/lib/fancyvpn/peers.json")
TRIAL_DB_PATH = os.environ.get("FANCY_TRIAL_DB", "/var/lib/fancyvpn/trials.json")
TOKEN_PATH = os.environ.get("FANCY_TOKEN_FILE", "/etc/fancyvpn/app_token")
WG = os.environ.get("FANCY_WG", "wg")
WG_QUICK = os.environ.get("FANCY_WG_QUICK", "wg-quick")
IFACE = "wg0"

NETWORK = ipaddress.ip_network("10.8.0.0/16")
RESERVED = {ipaddress.ip_address("10.8.0.1"), ipaddress.ip_address("10.8.0.2")}  # сервер и тестовый QR

RATE_LIMIT = 30          # не больше 30 НОВЫХ устройств
RATE_WINDOW = 3600       # в час с одного IP (повторные подключения не считаются)
MAX_BODY = 1024

with open(TOKEN_PATH) as f:
    APP_TOKEN = f.read().strip()

lock = threading.Lock()
rate = {}
trial_rate = {}


class RateLimited(Exception):
    pass


def valid_key(key):
    try:
        return isinstance(key, str) and len(base64.b64decode(key, validate=True)) == 32
    except Exception:
        return False


def load_db(path=DB_PATH):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_db(db, path=DB_PATH):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=1)
    os.replace(tmp, path)


def valid_device(d):
    return isinstance(d, str) and len(d) == 64 and all(c in "0123456789abcdef" for c in d)


def trial_first_seen(device, client):
    with lock:
        db = load_db(TRIAL_DB_PATH)
        if device not in db:
            if not rate_ok(client, trial_rate):
                raise RateLimited()
            db[device] = int(time.time())
            save_db(db, TRIAL_DB_PATH)
        return db[device]


def wg_peers():
    """Пиры, которые уже есть в WireGuard: {ключ: ip}. Включает добавленных вручную."""
    out = subprocess.run([WG, "show", IFACE, "allowed-ips"], capture_output=True, text=True, check=True).stdout
    peers = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and "/" in parts[1]:
            peers[parts[0]] = parts[1].split("/")[0]
    return peers


def allocate(used):
    for ip in NETWORK.hosts():
        if ip not in RESERVED and str(ip) not in used:
            return str(ip)
    raise RuntimeError("no free addresses")


def register(key, client):
    with lock:
        db = load_db()
        live = wg_peers()
        if key in db:
            ip = db[key]["ip"]
        elif key in live:
            ip = live[key]
        else:
            if not rate_ok(client, rate):
                raise RateLimited()
            used = {v["ip"] for v in db.values()} | set(live.values())
            ip = allocate(used)
        if live.get(key) != ip:
            subprocess.run([WG, "set", IFACE, "peer", key, "allowed-ips", ip + "/32"], check=True)
            subprocess.run([WG_QUICK, "save", IFACE], check=True, capture_output=True)
        if key not in db:
            db[key] = {"ip": ip, "created": int(time.time())}
            save_db(db)
        return ip


def rate_ok(client, table):
    """Вызывается под lock."""
    now = time.time()
    hits = [t for t in table.get(client, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_LIMIT:
        table[client] = hits
        return False
    hits.append(now)
    table[client] = hits
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "FancyVPN"
    sys_version = ""

    def log_message(self, *args):
        pass  # не храним IP и действия пользователей

    def reply(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/health":
            self.reply(200, {"ok": True})
        elif self.path == "/v1/info":
            try:
                with open("/etc/wireguard/server.pub") as f:
                    self.reply(200, {"public_key": f.read().strip()})
            except Exception:
                self.reply(500, {"error": "server_error"})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path not in ("/v1/register", "/v1/trial"):
            return self.reply(404, {"error": "not_found"})
        if not hmac.compare_digest(self.headers.get("X-App-Token", ""), APP_TOKEN):
            return self.reply(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError
            data = json.loads(self.rfile.read(length))
        except Exception:
            return self.reply(400, {"error": "bad_request"})
        if self.path == "/v1/trial":
            return self.trial(data)
        key = data.get("public_key") if isinstance(data, dict) else None
        if not valid_key(key):
            return self.reply(400, {"error": "bad_key"})
        try:
            ip = register(key, self.client_address[0])
        except RateLimited:
            return self.reply(429, {"error": "too_many_requests"})
        except Exception:
            return self.reply(500, {"error": "server_error"})
        self.reply(200, {"address": ip + "/32"})

    def trial(self, data):
        device = data.get("device") if isinstance(data, dict) else None
        if not valid_device(device):
            return self.reply(400, {"error": "bad_device"})
        try:
            first = trial_first_seen(device, self.client_address[0])
        except RateLimited:
            return self.reply(429, {"error": "too_many_requests"})
        except Exception:
            return self.reply(500, {"error": "server_error"})
        self.reply(200, {"first_seen": first, "now": int(time.time())})


if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

PYEOF
systemctl restart fancyvpn-api
sleep 2
curl -s http://127.0.0.1:8080/v1/health && echo && echo "Готово: сервер регистрации обновлён" || { echo "Ошибка, возвращаю старую версию"; cp /opt/fancyvpn/api.py.bak /opt/fancyvpn/api.py; systemctl restart fancyvpn-api; exit 1; }
