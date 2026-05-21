"""
schulki_proxy.py  –  Proxy für schulki.de (Railway-Version)
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
from urllib.parse   import urlparse, parse_qs
from urllib.error   import URLError, HTTPError
from http.cookiejar import CookieJar
import re, sys, os

PORT = int(os.environ.get("PORT", 8765))
HOST = "0.0.0.0"

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Accept, Content-Type",
}

jar    = CookieJar()
opener = build_opener(HTTPCookieProcessor(jar))
csrf_token = None

def fetch_csrf_token():
    global csrf_token
    try:
        req = Request("https://schulki.de/login", headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        match = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html)
        if match:
            csrf_token = match.group(1)
            print(f"  CSRF-Token geholt: {csrf_token[:20]}...")
        else:
            for cookie in jar:
                if cookie.name == "XSRF-TOKEN":
                    from urllib.parse import unquote
                    csrf_token = unquote(cookie.value)
                    print(f"  CSRF-Token aus Cookie: {csrf_token[:20]}...")
                    break
    except Exception as e:
        print(f"  Warnung: CSRF-Token konnte nicht geholt werden: {e}")


class ProxyHandler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self):
        global csrf_token
        target = self._target_url()
        if not target:
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""

        if csrf_token:
            extra = f"&_token={csrf_token}".encode()
            body  = body + extra

        headers = {
            "Content-Type":  self.headers.get("Content-Type", "application/x-www-form-urlencoded"),
            "Accept":        "application/json, text/plain, */*",
            "User-Agent":    "Mozilla/5.0",
            "X-CSRF-TOKEN":  csrf_token or "",
            "Referer":       "https://schulki.de/",
        }
        auth = self.headers.get("Authorization")
        if auth:
            headers["Authorization"] = auth

        try:
            req = Request(target, data=body, headers=headers, method="POST")
            with opener.open(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
        except HTTPError as e:
            body_err = e.read()
            print(f"  HTTP-Fehler {e.code}: {body_err[:200]}")
            if e.code == 419:
                print("  → CSRF-Token abgelaufen, hole neuen...")
                fetch_csrf_token()
            self._error(e.code, str(e))
        except URLError as e:
            self._error(502, str(e))

    def do_GET(self):
        target = self._target_url()
        if not target:
            return

        headers = {
            "Accept":     "text/event-stream",
            "User-Agent": "Mozilla/5.0",
            "Referer":    "https://schulki.de/",
        }
        auth = self.headers.get("Authorization")
        if auth:
            headers["Authorization"] = auth

        try:
            req = Request(target, headers=headers, method="GET")
            with opener.open(req, timeout=90) as resp:
                self.send_response(resp.status)
                ct = resp.headers.get("Content-Type", "text/event-stream")
                self.send_header("Content-Type", ct)
                self.send_header("Cache-Control",    "no-cache")
                self.send_header("X-Accel-Buffering","no")
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                while True:
                    chunk = resp.read(512)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except BrokenPipeError:
                        break
        except HTTPError as e:
            self._error(e.code, str(e))
        except URLError as e:
            self._error(502, str(e))

    def _target_url(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        url    = params.get("url", [None])[0]
        if not url:
            self._error(400, "Fehlender 'url'-Parameter")
            return None
        return url

    def _error(self, code, msg):
        body = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type",   "text/plain")
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"  [{self.address_string()}] {fmt % args}")


if __name__ == "__main__":
    print("=" * 50)
    print("  Hole CSRF-Token von schulki.de ...")
    fetch_csrf_token()
    print("  ✓ Bereit." if csrf_token else "  ⚠ Kein CSRF-Token.")
    print()
    server = HTTPServer((HOST, PORT), ProxyHandler)
    print(f"  Proxy läuft auf {HOST}:{PORT}")
    print("=" * 50)
    server.serve_forever()
