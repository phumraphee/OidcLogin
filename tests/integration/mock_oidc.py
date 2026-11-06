#!/usr/bin/env python3
"""A tiny OpenID Connect provider for tests — never for real use.

  python3 mock_oidc.py --port 18443 --cert cert.pem --key key.pem --client-id CID --client-secret SEC

Serves https://localhost:<port>: discovery, /authorize (approves at once, no login screen),
/token (checks client secret, code, redirect_uri and PKCE), /userinfo. What the next sign-in
returns is set by POST /_scenario with JSON, e.g.
  {"sub": "s-1", "preferred_username": "jane", "groups": ["staff"], "email_verified": true,
   "nonce_override": null, "iss_override": null, "aud_override": null, "exp_offset": 300,
   "userinfo_sub": null, "reuse_code": false}
GET /_log returns what the provider saw (for assertions).

Logout, as Pocket ID 2.19.1 does it (2026-10-22): the browser's log-in at the provider is a
cookie (mock_sid), made at the first /authorize. GET /api/oidc/end-session notes the
id_token_hint and sends the browser to /logout (no Logout Callback URL registered); GET
/logout is the "log out?" page, POST /logout ends the browser's log-in. With the scenario's
"need_login": true, /authorize without that log-in shows a sign-in page instead of approving;
with prompt=none it answers error=login_required at once.
"""
import argparse, base64, hashlib, json, secrets, ssl, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"scenario": {}, "codes": {}, "tokens": {}, "log": [], "users": [], "users_down": False, "sessions": set()}
LOCK = threading.Lock()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class H(BaseHTTPRequestHandler):
    server_version = "mock-oidc"

    def log_message(self, *a):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, text, code=200):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def note(self, what, **kw):
        with LOCK:
            STATE["log"].append(dict(what=what, **kw))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        iss = self.server.issuer
        if u.path == "/.well-known/openid-configuration":
            return self.send_json({
                "issuer": iss,
                "authorization_endpoint": iss + "/authorize",
                "token_endpoint": iss + "/token",
                "userinfo_endpoint": iss + "/userinfo",
                "code_challenge_methods_supported": ["S256"],
                "end_session_endpoint": iss + "/api/oidc/end-session",
            })
        if u.path == "/authorize":
            self.note("authorize", **q)
            if q.get("client_id") != self.server.client_id or q.get("response_type") != "code":
                return self.send_json({"error": "bad request"}, 400)
            sid = self.cookie("mock_sid")
            with LOCK:
                known = sid in STATE["sessions"]
                need = bool(STATE["scenario"].get("need_login"))
            if not known and q.get("prompt") == "none":
                # prompt=none and no log-in here: the answer goes back at once (no page)
                self.note("login_required", **q)
                loc = q["redirect_uri"] + ("&" if "?" in q["redirect_uri"] else "?") + urllib.parse.urlencode(
                    {"error": "login_required", "state": q.get("state", "")})
                self.send_response(302)
                self.send_header("Location", loc)
                self.end_headers()
                return
            if not known and need:
                # nobody is logged in at the provider in this browser: its sign-in page
                self.note("login_page")
                return self.send_html("<h1>Sign in</h1><p>login required</p>")
            new_sid = None
            if not known:
                # the person signs in at the provider (here at once): the browser's log-in
                new_sid = secrets.token_urlsafe(16)
                with LOCK:
                    STATE["sessions"].add(new_sid)
            code = secrets.token_urlsafe(24)
            with LOCK:
                STATE["codes"][code] = dict(q, at=time.time())
            loc = q["redirect_uri"] + ("&" if "?" in q["redirect_uri"] else "?") + urllib.parse.urlencode(
                {"code": code, "state": q.get("state", "")})
            self.send_response(302)
            self.send_header("Location", loc)
            if new_sid:
                self.send_header("Set-Cookie", "mock_sid=%s; Path=/; Secure; HttpOnly" % new_sid)
            self.end_headers()
            return
        if u.path == "/api/oidc/end-session":
            self.note("end_session", **q)
            self.send_response(302)
            self.send_header("Location", iss + "/logout")
            self.end_headers()
            return
        if u.path == "/logout":
            self.note("logout_page")
            return self.send_html('<h1>Log out?</h1><form method="post" action="/logout"><button>Log out</button></form>')
        if u.path == "/userinfo":
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            with LOCK:
                sc = STATE["tokens"].get(tok)
            if not sc:
                return self.send_json({"error": "invalid_token"}, 401)
            info = {"sub": sc.get("userinfo_sub") or sc["sub"]}
            for k in ("preferred_username", "groups", "email_verified", "email", "name"):
                if k in sc:
                    info[k] = sc[k]
            self.note("userinfo", sub=info["sub"])
            return self.send_json(info)
        if u.path == "/api/users":
            # Pocket ID's admin list (X-API-Key) — paginated like the real one
            if STATE["users_down"]:
                return self.send_json({"error": "down"}, 503)
            if not self.server.api_key or self.headers.get("X-API-Key") != self.server.api_key:
                return self.send_json({"error": "unauthorized"}, 401)
            page = int(q.get("pagination[page]", "1")); limit = int(q.get("pagination[limit]", "20"))
            with LOCK:
                users = list(STATE["users"])
            chunk = users[(page - 1) * limit: page * limit]
            pages = max(1, (len(users) + limit - 1) // limit)
            self.note("users", page=page)
            return self.send_json({"data": chunk, "pagination": {"totalPages": pages, "totalItems": len(users), "currentPage": page, "itemsPerPage": limit}})
        if u.path == "/_log":
            with LOCK:
                return self.send_json(STATE["log"])
        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode()
        if u.path == "/logout":
            sid = self.cookie("mock_sid")
            with LOCK:
                STATE["sessions"].discard(sid)
            self.note("logged_out", had=bool(sid))
            self.send_response(200)
            self.send_header("Set-Cookie", "mock_sid=; Path=/; Max-Age=0; Secure; HttpOnly")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<p>You are logged out.</p>")
            return
        if u.path == "/_users":
            body = json.loads(raw or "{}")
            with LOCK:
                STATE["users"] = body.get("users", [])
                STATE["users_down"] = bool(body.get("down", False))
            return self.send_json({"ok": True})
        if u.path == "/_scenario":
            with LOCK:
                STATE["scenario"] = json.loads(raw or "{}")
                STATE["log"] = []
            return self.send_json({"ok": True})
        if u.path == "/token":
            form = dict(urllib.parse.parse_qsl(raw))
            auth = self.headers.get("Authorization", "")
            try:
                cid, sec = base64.b64decode(auth[6:]).decode().split(":", 1)
                cid, sec = urllib.parse.unquote(cid), urllib.parse.unquote(sec)
            except Exception:
                cid = sec = None
            self.note("token", client=cid, grant=form.get("grant_type"))
            if cid != self.server.client_id or sec != self.server.client_secret:
                return self.send_json({"error": "invalid_client"}, 401)
            with LOCK:
                sc = dict(STATE["scenario"])
                code = form.get("code", "")
                # reuse_code: a careless provider that accepts a code twice — to prove the
                # client's own one-use state, not the provider, stops a replay
                req = STATE["codes"].get(code) if sc.get("reuse_code") else STATE["codes"].pop(code, None)
            if not req or time.time() - req["at"] > 60:
                return self.send_json({"error": "invalid_grant"}, 400)
            if form.get("redirect_uri") != req.get("redirect_uri"):
                return self.send_json({"error": "invalid_grant", "why": "redirect_uri"}, 400)
            chal = b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
            if req.get("code_challenge_method") != "S256" or chal != req.get("code_challenge"):
                return self.send_json({"error": "invalid_grant", "why": "pkce"}, 400)
            now = int(time.time())
            claims = {
                "iss": sc.get("iss_override") or self.server.issuer,
                "aud": sc.get("aud_override") or self.server.client_id,
                "sub": sc.get("sub", "s-1"),
                "nonce": sc.get("nonce_override") or req.get("nonce"),
                "iat": now,
                "exp": now + int(sc.get("exp_offset", 300)),
            }
            idt = b64url(b'{"alg":"RS256","typ":"JWT"}') + "." + b64url(json.dumps(claims).encode()) + ".bm90LXNpZ25lZA"
            at = secrets.token_urlsafe(24)
            with LOCK:
                STATE["tokens"][at] = sc
            return self.send_json({"access_token": at, "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
        self.send_json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--client-id", required=True)
    ap.add_argument("--client-secret", required=True)
    ap.add_argument("--api-key", default="")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    srv.issuer = "https://localhost:%d" % a.port
    srv.client_id, srv.client_secret = a.client_id, a.client_secret
    srv.api_key = a.api_key
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
