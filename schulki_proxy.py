"""
schulki_proxy.py  –  Lokaler Proxy für schulki.de
Starten mit:  python schulki_proxy.py
Läuft dann auf:  http://localhost:8765

Neu: Per-Session-Isolation über den ?_sid=... Parameter.
Jeder Browser-Tab bekommt seinen eigenen Cookie-Jar →
eigene schulki.de-Session → eigene Konversation, kein Durchmischen.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.parse   import urlparse, parse_qs, unquote
from urllib.error   import URLError, HTTPError
from http.cookiejar import CookieJar
import re, sys, threading, os

PORT = int(os.environ.get("PORT", 8765))

CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Accept, Content-Type",
}

# ── Per-Session Cookie-Jars ─────────────────────────────────────────────────
# Jeder Browser-Tab schickt einen eindeutigen _sid-Parameter.
# Damit bekommt jeder Tab seinen eigenen Cookie-Jar und damit
# seine eigene schulki.de-Sitzung (= eigene Konversation).

_sessions      = {}   # { sid: {"opener": ..., "csrf": ...} }
_sessions_lock = threading.Lock()

def _get_session(sid):
    """Gibt den Opener (+ CSRF) für eine Session-ID zurück.
    Erstellt eine neue Session falls noch keine existiert."""
    with _sessions_lock:
        if sid not in _sessions:
            jar    = CookieJar()
            opener = build_opener(HTTPCookieProcessor(jar))
            _sessions[sid] = {"opener": opener, "jar": jar, "csrf": None}
            # Neue Session sofort mit CSRF initialisieren
            threading.Thread(
                target=_init_session,
                args=(sid,),
                daemon=True
            ).start()
        return _sessions[sid]

def _init_session(sid):
    """Holt CSRF-Token für eine neue Session (läuft im Hintergrund)."""
    sess = _sessions.get(sid)
    if not sess:
        return
    try:
        req = Request("https://schulki.de/login",
                      headers={"User-Agent": "Mozilla/5.0"})
        with sess["opener"].open(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        m = re.search(
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            html)
        if m:
            sess["csrf"] = m.group(1)
        else:
            for cookie in sess["jar"]:
                if cookie.name == "XSRF-TOKEN":
                    sess["csrf"] = unquote(cookie.value)
                    break
        print(f"  Session {sid[:8]}: CSRF-Token bereit.")
    except Exception as e:
        print(f"  Session {sid[:8]}: CSRF-Initialisierung fehlgeschlagen: {e}")


# Fallback-Session für Anfragen ohne _sid (z. B. Teacher-Einstellungen)
_fallback_jar    = CookieJar()
_fallback_opener = build_opener(HTTPCookieProcessor(_fallback_jar))
_fallback_csrf   = None

def _init_fallback():
    global _fallback_csrf
    try:
        req = Request("https://schulki.de/login",
                      headers={"User-Agent": "Mozilla/5.0"})
        with _fallback_opener.open(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        m = re.search(
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
            html)
        if m:
            _fallback_csrf = m.group(1)
            print(f"  Fallback CSRF-Token: {_fallback_csrf[:20]}...")
        else:
            for cookie in _fallback_jar:
                if cookie.name == "XSRF-TOKEN":
                    _fallback_csrf = unquote(cookie.value)
                    print(f"  Fallback CSRF aus Cookie: {_fallback_csrf[:20]}...")
                    break
    except Exception as e:
        print(f"  Fallback CSRF fehlgeschlagen: {e}")


# ── Handler ──────────────────────────────────────────────────────────────────

class ProxyHandler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self):
        target, opener, csrf = self._resolve()
        if not target:
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""

        if csrf:
            body += f"&_token={csrf}".encode()

        headers = {
            "Content-Type": self.headers.get(
                "Content-Type", "application/x-www-form-urlencoded"),
            "Accept":       "application/json, text/plain, */*",
            "User-Agent":   "Mozilla/5.0",
            "X-CSRF-TOKEN": csrf or "",
            "Referer":      "https://schulki.de/",
        }
        auth = self.headers.get("Authorization")
        if auth:
            headers["Authorization"] = auth

        try:
            req = Request(target, data=body, headers=headers, method="POST")
            with opener.open(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type",
                                 resp.headers.get("Content-Type",
                                                  "application/json"))
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
        except HTTPError as e:
            body_err = e.read()
            print(f"  HTTP-Fehler {e.code}: {body_err[:200]}")
            if e.code == 419:
                print("  → CSRF abgelaufen, initialisiere Session neu …")
                _init_fallback()
            self._error(e.code, str(e))
        except URLError as e:
            self._error(502, str(e))

    def do_GET(self):
        target, opener, _ = self._resolve()
        if not target:
            return

        headers = {
            "Accept":     self.headers.get("Accept", "text/event-stream"),
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
                self.send_header("Cache-Control",     "no-cache")
                self.send_header("X-Accel-Buffering", "no")
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

    # ── Hilfsmethoden ───────────────────────────────────────────

    def _resolve(self):
        """Gibt (target_url, opener, csrf_token) zurück."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        url = params.get("url", [None])[0]
        if not url:
            self._error(400, "Fehlender 'url'-Parameter")
            return None, None, None

        sid = params.get("_sid", [None])[0]
        if sid:
            sess   = _get_session(sid)
            opener = sess["opener"]
            csrf   = sess["csrf"]
        else:
            opener = _fallback_opener
            csrf   = _fallback_csrf

        return url, opener, csrf

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


# ── Server starten ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 52)
    print("  Initialisiere Fallback-Session …")
    _init_fallback()
    print()
    host = "0.0.0.0" if os.environ.get("PORT") else "localhost"
    try:
        server = HTTPServer((host, PORT), ProxyHandler)
        print(f"  schulki Proxy läuft auf http://{host}:{PORT}")
        print(f"  Per-Session-Isolation: aktiv (_sid-Parameter)")
        print(f"  Fenster offen lassen während du chattest.")
        print(f"  Stoppen mit: Strg+C")
        print("=" * 52)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProxy gestoppt.")
        sys.exit(0)
    except OSError:
        print(f"\nFehler: Port {PORT} ist bereits belegt.")
        sys.exit(1)
