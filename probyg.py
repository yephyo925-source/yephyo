# ============================================================
#  GYAN PROXY BOT �� PART 1: CONFIG
#  Developer by NgaTon
# ============================================================

import base64
import concurrent.futures
import io
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.request
from urllib.parse import urlsplit

import telebot
from telebot import types

# ---------- CONFIG ----------
BOT_NAME    = "Gyan"
BOT_TOKEN   = os.environ.get("BOT_TOKEN", "8938438812:AAFNoj12Wyw2x5wij6yIX7eSGRspibcldhM")
TARGET_HOST = "example.com"
TARGET_PORT = 443
IP_CHECK_URL = "https://api.ipify.org?format=json"
UA           = "Gyan-ProxyBot/1.0"
TIMEOUT      = 5.0
WORKERS      = 100
MAX_WANTED   = 200

SOURCES = [
    ("TheSpeedX HTTP",   "http",   "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("TheSpeedX SOCKS4", "socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"),
    ("TheSpeedX SOCKS5", "socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    ("monosans HTTP",    "http",   "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("monosans HTTPS",   "https",  "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt"),
    ("monosans SOCKS4",  "socks4", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
    ("monosans SOCKS5",  "socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    ("jetkai HTTP",      "http",   "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"),
    ("jetkai SOCKS5",    "socks5", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"),
    ("proxifly all",     "auto",   "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"),
]

bot = telebot.TeleBot(BOT_TOKEN)
active_jobs = {}   # chat_id -> True
# ============================================================
#  GYAN PROXY BOT �� PART 2: PROXY CORE
# ============================================================

def parse_entry(line, default_protocol=""):
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        try:
            p = urlsplit(line)
            scheme = p.scheme.lower()
            if scheme not in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
                return None
            if not p.hostname or p.port is None:
                return None
            return {"raw": line, "host": p.hostname, "port": p.port,
                    "user": p.username, "password": p.password, "hint": scheme}
        except (ValueError, TypeError):
            return None
    if "@" in line:
        auth, endpoint = line.rsplit("@", 1)
        if ":" in auth and ":" in endpoint:
            user, password = auth.split(":", 1)
            host, port = endpoint.rsplit(":", 1)
            try:
                port = int(port)
                if host and 1 <= port <= 65535:
                    return {"raw": line, "host": host.strip("[]"), "port": port,
                            "user": user, "password": password, "hint": default_protocol}
            except ValueError:
                return None
    bits = line.split(":")
    try:
        if len(bits) == 2:
            host, port = bits
            user = password = None
        elif len(bits) == 4:
            host, port, user, password = bits
        else:
            return None
        port = int(port)
        if not host or not 1 <= port <= 65535:
            return None
        return {"raw": line, "host": host.strip("[]"), "port": port,
                "user": user, "password": password, "hint": default_protocol}
    except ValueError:
        return None


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("Connection closed")
        data += chunk
    return data


def read_headers(sock, limit=16384):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(min(2048, limit - len(data)))
        if not chunk:
            break
        data += chunk
    if b"\r\n\r\n" not in data:
        raise OSError("Invalid HTTP headers")
    return data


def auth_header(proxy):
    if proxy.get("user") is None:
        return ""
    value = (proxy["user"] + ":" + (proxy.get("password") or "")).encode()
    return "Proxy-Authorization: Basic " + base64.b64encode(value).decode() + "\r\n"


def open_sock(proxy, timeout):
    s = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    s.settimeout(timeout)
    return s


def http_connect(proxy, timeout, tls_proxy=False):
    s = open_sock(proxy, timeout)
    try:
        if tls_proxy:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=proxy["host"])
        req = (f"CONNECT {TARGET_HOST}:{TARGET_PORT} HTTP/1.1\r\n"
               f"Host: {TARGET_HOST}:{TARGET_PORT}\r\n{auth_header(proxy)}"
               f"User-Agent: {UA}\r\nProxy-Connection: Keep-Alive\r\n\r\n")
        s.sendall(req.encode("ascii"))
        first = read_headers(s).split(b"\r\n", 1)[0].decode("latin1", "replace")
        m = re.search(r"\s(\d{3})(?:\s|$)", first)
        if not m:
            raise OSError("Bad HTTP response")
        code = int(m.group(1))
        if code != 200:
            raise OSError(f"CONNECT {code}")
        return s
    except Exception:
        s.close()
        raise


def socks5_connect(proxy, timeout):
    s = open_sock(proxy, timeout)
    try:
        user = proxy.get("user")
        if user is None:
            s.sendall(b"\x05\x01\x00")
            if recv_exact(s, 2) != b"\x05\x00":
                raise OSError("SOCKS5 no-auth failed")
        else:
            s.sendall(b"\x05\x02\x00\x02")
            rep = recv_exact(s, 2)
            if rep[0] != 5 or rep[1] == 255:
                raise OSError("SOCKS5 auth failed")
            if rep[1] == 2:
                u, p = user.encode(), (proxy.get("password") or "").encode()
                if len(u) > 255 or len(p) > 255:
                    raise OSError("Creds too long")
                s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
                if recv_exact(s, 2)[1] != 0:
                    raise OSError("SOCKS5 creds rejected")
        host = TARGET_HOST.encode("ascii")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + TARGET_PORT.to_bytes(2, "big"))
        head = recv_exact(s, 4)
        if head[0] != 5 or head[1] != 0:
            raise OSError(f"SOCKS5 reject {head[1]}")
        if head[3] == 1:
            recv_exact(s, 6)
        elif head[3] == 4:
            recv_exact(s, 18)
        elif head[3] == 3:
            n = recv_exact(s, 1)[0]
            recv_exact(s, n + 2)
        return s
    except Exception:
        s.close()
        raise


def socks4_connect(proxy, timeout):
    s = open_sock(proxy, timeout)
    try:
        user = (proxy.get("user") or "").encode("utf-8")
        host = TARGET_HOST.encode("ascii") + b"\x00"
        s.sendall(b"\x04\x01" + TARGET_PORT.to_bytes(2, "big") +
                  b"\x00\x00\x00\x01" + user + b"\x00" + host)
        reply = recv_exact(s, 8)
        if reply[1] != 0x5A:
            raise OSError(f"SOCKS4 reject {reply[1]}")
        return s
    except Exception:
        s.close()
        raise


def test_protocol(proxy, proto, timeout):
    sock = None
    started = time.perf_counter()
    try:
        if proto == "http":
            sock = http_connect(proxy, timeout, False)
        elif proto == "https":
            sock = http_connect(proxy, timeout, True)
        elif proto in ("socks5", "socks5h"):
            sock = socks5_connect(proxy, timeout)
        elif proto in ("socks4", "socks4a"):
            sock = socks4_connect(proxy, timeout)
        else:
            raise OSError("Unsupported")
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=TARGET_HOST)
        tls.getpeercert()
        tls.close()
        return True, (time.perf_counter() - started) * 1000, ""
    except Exception as exc:
        if sock:
            try: sock.close()
            except: pass
        return False, (time.perf_counter() - started) * 1000, str(exc)[:80]


def check_proxy(proxy, timeout):
    hint = proxy.get("hint", "")
    if hint in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
        order = [hint] + [p for p in ("http", "https", "socks5", "socks4") if p != hint]
    else:
        order = ["http", "https", "socks5", "socks4"]
    for proto in order:
        ok, ms, _ = test_protocol(proxy, proto, timeout)
        if ok:
            return {"proxy": proxy["raw"], "host": proxy["host"], "port": proxy["port"],
                    "status": "WORKING", "type": proto.upper(), "ms": ms}
    return None


def fetch_source(source, timeout):
    name, proto, url = source
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=max(timeout, 6.0)) as r:
            body = r.read(8 * 1024 * 1024).decode("utf-8", "replace")
        entries = []
        for line in body.splitlines():
            item = parse_entry(line, proto if proto != "auto" else "")
            if item:
                entries.append(item)
        return name, entries
    except Exception:
        return name, []
# ============================================================
#  GYAN PROXY BOT �� PART 3: HANDLERS & RUNNER
# ============================================================

def run_check_job(chat_id, entries, wanted, msg_id=None):
    total = len(entries)
    working = []
    completed = 0
    last_update = 0.0

    def progress_text():
        return (f"�9�3 *{BOT_NAME} is checking...*\n"
                f"Progress: `{completed}/{total}`\n"
                f"�7�3 Working: `{len(working)}`\n"
                f"�9�3 Wanted: `{wanted}`")

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(check_proxy, e, TIMEOUT): e for e in entries}
        for fut in concurrent.futures.as_completed(futures):
            try:
                r = fut.result()
            except Exception:
                r = None
            completed += 1
            if r:
                working.append(r)

            now = time.time()
            if now - last_update > 3:
                last_update = now
                try:
                    bot.edit_message_text(progress_text(), chat_id, msg_id,
                                          parse_mode="Markdown")
                except Exception:
                    pass

            if wanted and len(working) >= wanted:
                for f in futures:
                    f.cancel()
                break

    working.sort(key=lambda x: x["ms"])

    summary = (f"�7�3 *{BOT_NAME} finished!*\n"
               f"Tested: `{completed}`\n"
               f"Working: `{len(working)}`\n"
               f"Time: `{time.strftime('%H:%M:%S')}`")
    try:
        bot.edit_message_text(summary, chat_id, msg_id, parse_mode="Markdown")
    except Exception:
        bot.send_message(chat_id, summary, parse_mode="Markdown")

    if not working:
        bot.send_message(chat_id, "�0�0 No working proxies found. Try again later.")
        return

    selected = working[:wanted] if wanted else working
    lines = [f"{r['type'].lower()}://{r['host']}:{r['port']}" for r in selected]
    text = "\n".join(lines)

    preview = "\n".join(f"`{l}`" for l in lines[:15])
    bot.send_message(chat_id,
                     f"�9�5 *Top {min(15, len(lines))} proxies:*\n{preview}",
                     parse_mode="Markdown")

    buf = io.BytesIO(text.encode("utf-8"))
    buf.name = "gyan_working_proxies.txt"
    bot.send_document(chat_id, buf,
                      caption=f"�9�4 {len(selected)} working proxies from {BOT_NAME}")


# ---------- /start ----------
@bot.message_handler(commands=["start"])
def cmd_start(msg):
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    kb.row("�9�3 Hunt 20", "�9�3 Hunt 50")
    kb.row("�9�7 Paste list", "�6�7�1�5 Help")
    bot.send_message(
        msg.chat.id,
        f"�9�9 *Welcome to {BOT_NAME} Proxy Bot!*\n\n"
        "Public list �3�6�3�1�3�9�3�0�3�0�3�9 proxy �3�7�3�2�3�4�3�1�3�0�3�6�3�6 CONNECT + TLS test �3�0�3�0�3�5 �3�5�3�5�3�8�3�6�3�9�3�6�3�1�3�9�3�6�3�6�3�6�3�8�3�5\n\n"
        "*Commands:*\n"
        "�6�1 `/hunt N` �� working N �3�1�3�7 �3�7�3�2�3�4\n"
        "�6�1 `/check` �� �3�0�3�4�3�5�3�8 list �3�0�3�5�3�7 �3�5�3�5�3�8\n"
        "�6�1 `/help` �� �3�3�3�0�3�8�3�3�3�0�3�6\n\n"
        "�7�2�1�5 _Public proxies �3�0�3�5�3�7 password/OTP/banking �3�3�3�6�3�1�3�0�3�8 �3�5�3�0�3�7�3�4�3�6�3�1�3�3�3�0�3�0�3�5�3�5_",
        parse_mode="Markdown", reply_markup=kb)


# ---------- /help ----------
@bot.message_handler(commands=["help"])
def cmd_help(msg):
    bot.send_message(
        msg.chat.id,
        f"*�9�8 {BOT_NAME} Help*\n\n"
        "1�1�5�6�6 `/hunt 30` �� public list �3�0�3�0�3�9 working 30 �3�1�3�7 �3�7�3�2�3�4\n"
        "2�1�5�6�6 `/check` �� proxy list �3�1�3�5�3�7�3�5 (�3�6�3�5�3�8�3�0�3�0�3�9�3�4�3�4�3�8�3�6�3�6�3�5�3�8�3�1�3�7) �3�0�3�5�3�7�3�5�3�5�3�1�3�7�3�6�3�8 `.txt` file\n\n"
        "*Formats:*\n"
        "`1.2.3.4:8080`\n"
        "`socks5://1.2.3.4:1080`\n"
        "`user:pass@1.2.3.4:8080`\n\n"
        "�7�2�1�5 _Results reflect this server's network at test time._",
        parse_mode="Markdown")


# ---------- /hunt ----------
@bot.message_handler(commands=["hunt"])
def cmd_hunt(msg):
    parts = msg.text.split()
    wanted = 20
    if len(parts) > 1:
        try:
            wanted = max(1, min(int(parts[1]), MAX_WANTED))
        except ValueError:
            pass

    if msg.chat.id in active_jobs:
        bot.reply_to(msg, f"�7�7 {BOT_NAME} already running a job for you.")
        return

    sent = bot.send_message(msg.chat.id, f"�9�9 {BOT_NAME} is fetching public proxy lists...")
    active_jobs[msg.chat.id] = True

    def worker():
        try:
            entries = []
            for src in SOURCES:
                _, got = fetch_source(src, TIMEOUT)
                entries.extend(got)

            seen, unique = set(), []
            for e in entries:
                k = (e["host"], e["port"], e.get("user"), e.get("password"))
                if k not in seen:
                    seen.add(k)
                    unique.append(e)

            if not unique:
                bot.edit_message_text("�7�4 Could not fetch any proxies. Try later.",
                                      msg.chat.id, sent.message_id)
                return

            bot.edit_message_text(
                f"�9�4 Fetched *{len(unique)}* unique proxies\n"
                f"�9�3 Testing for *{wanted}* working...",
                msg.chat.id, sent.message_id, parse_mode="Markdown")

            run_check_job(msg.chat.id, unique, wanted, sent.message_id)
        except Exception as e:
            try:
                bot.edit_message_text(f"�7�4 Error: {e}", msg.chat.id, sent.message_id)
            except Exception:
                pass
        finally:
            active_jobs.pop(msg.chat.id, None)

    threading.Thread(target=worker, daemon=True).start()


# ---------- /check ----------
@bot.message_handler(commands=["check"])
def cmd_check(msg):
    bot.send_message(
        msg.chat.id,
        "�9�7 Send your proxy list (one per line) or upload a `.txt` file.\n"
        "Add `[20]` at the end for wanted count.",
        parse_mode="Markdown")
    bot.register_next_step_handler(msg, receive_list)


def receive_list(msg):
    wanted = 20
    content = ""

    if msg.document:
        try:
            file_info = bot.get_file(msg.document.file_id)
            downloaded = bot.download_file(file_info.file_path)
            content = downloaded.decode("utf-8", "replace")
        except Exception as e:
            bot.reply_to(msg, f"�7�4 Cannot read file: {e}")
            return
    elif msg.text:
        content = msg.text
    else:
        bot.reply_to(msg, "�7�4 Please send text or .txt file.")
        return

    m = re.search(r"\[(\d+)\]", content)
    if m:
        wanted = max(1, min(int(m.group(1)), MAX_WANTED))
        content = content.replace(m.group(0), "")

    entries = []
    for line in content.splitlines():
        item = parse_entry(line)
        if item:
            entries.append(item)

    if not entries:
        bot.reply_to(msg, "�7�4 No valid proxies found in your message.")
        return

    if msg.chat.id in active_jobs:
        bot.reply_to(msg, f"�7�7 {BOT_NAME} already running a job for you.")
        return

    sent = bot.send_message(
        msg.chat.id,
        f"�9�3 {BOT_NAME} testing *{len(entries)}* proxies for *{wanted}* working...",
        parse_mode="Markdown")
    active_jobs[msg.chat.id] = True

    def worker():
        try:
            run_check_job(msg.chat.id, entries, wanted, sent.message_id)
        finally:
            active_jobs.pop(msg.chat.id, None)

    threading.Thread(target=worker, daemon=True).start()


# ---------- Quick buttons ----------
@bot.message_handler(func=lambda m: m.text == "�9�3 Hunt 20")
def quick20(m):
    m.text = "/hunt 20"; cmd_hunt(m)

@bot.message_handler(func=lambda m: m.text == "�9�3 Hunt 50")
def quick50(m):
    m.text = "/hunt 50"; cmd_hunt(m)

@bot.message_handler(func=lambda m: m.text == "�9�7 Paste list")
def quick_paste(m):
    cmd_check(m)

@bot.message_handler(func=lambda m: m.text == "�6�7�1�5 Help")
def quick_help(m):
    cmd_help(m)


# ---------- RUN ----------
if __name__ == "__main__":
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("�7�4 Set BOT_TOKEN first!")
        print("   export BOT_TOKEN='123456:ABC...'")
        raise SystemExit(1)
    print(f"�0�6 {BOT_NAME} Proxy Bot is running...")
    print("   Press Ctrl+C to stop.")
    bot.infinity_polling(timeout=30, long_polling_timeout=30)
