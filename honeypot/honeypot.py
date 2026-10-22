import socket, threading, json, datetime, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

LOG = pathlib.Path(__file__).resolve().parent.parent / "logs" / "honeypot.jsonl"
LOG.parent.mkdir(exist_ok=True)
lock = threading.Lock()

def log(service, ip, port, event, **extra):
    rec = {"time": datetime.datetime.now().isoformat(timespec="seconds"),
           "service": service, "src_ip": ip, "src_port": port,
           "event": event, **extra}
    with lock:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    print(rec)

# ---------- fake SSH: shows a banner, records what the client sends ----------
def handle_ssh(conn, addr):
    try:
        conn.settimeout(10)
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        data = conn.recv(1024)
        log("ssh", addr[0], addr[1], "connection",
            client_banner=data.decode(errors="replace").strip()[:200])
    except Exception:
        pass
    finally:
        conn.close()

def ssh_server(port=2222):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(50)
    print(f"SSH honeypot on port {port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_ssh, args=(conn, addr), daemon=True).start()

# ---------- fake web admin login: records requests and credentials ----------
PAGE = b"""<html><body><h2>Admin Portal</h2>
<form method="post" action="/login">
User: <input name="username"><br>Pass: <input name="password" type="password"><br>
<button>Login</button></form></body></html>"""

class Web(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        log("http", *self.client_address, "GET", path=self.path,
            user_agent=self.headers.get("User-Agent", ""))
        self.reply(200, PAGE)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(n).decode(errors="replace"))
        log("http", *self.client_address, "login_attempt", path=self.path,
            username=form.get("username", [""])[0],
            password=form.get("password", [""])[0],
            user_agent=self.headers.get("User-Agent", ""))
        self.reply(401, b"<html><body>Invalid credentials</body></html>")

if __name__ == "__main__":
    threading.Thread(target=ssh_server, daemon=True).start()
    print("HTTP honeypot on port 8080. Press Ctrl+C to stop.")
    ThreadingHTTPServer(("0.0.0.0", 8080), Web).serve_forever()