"""
xera_extras.py - drop-in add-on for Xera Company Backend (backend.py)

Adds, without rewriting backend.py:
  * Signed + verified JWTs (the original accepted ANY token and trusted its "uid")
  * Safe client-IP detection (the original trusted the first X-Forwarded-For
    value, which any player can spoof - including to become DEV_IP)
  * Per-IP rate limiting (stricter on the authenticate endpoints)
  * Persistent bans stored in SQLite (usernames + IPs), no file editing needed
  * Admin API  (/admin/stats, /admin/ban, /admin/unban, /admin/grant, /admin/reports)
  * A real friends system (the original returned empty stubs)
  * Health check, request IDs, structured request logging
  * Weekend-mode switch via env var (always | auto | off)
  * SQLite backup helper:  python xera_extras.py backup [dest_dir]

Setup: see PATCHES.md. Environment variables (all optional):
  XERA_JWT_SECRET            signing key (auto-generated + saved to jwt_secret.key if unset)
  XERA_TRUSTED_PROXY_HOPS    reverse proxies in front of the app (default 1; use 0 if none)
  XERA_RATE_LIMIT_PER_MIN    per-IP requests/minute (default 600)
  XERA_AUTH_RATE_LIMIT_PER_MIN  per-IP auth requests/minute (default 30)
  XERA_WEEKEND_MODE          always (default, matches your current behaviour) | auto | off
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

log = logging.getLogger("xera")

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
TRUSTED_PROXY_HOPS = int(os.environ.get("XERA_TRUSTED_PROXY_HOPS", "1"))
RATE_LIMIT_PER_MIN = int(os.environ.get("XERA_RATE_LIMIT_PER_MIN", "600"))
AUTH_RATE_LIMIT_PER_MIN = int(os.environ.get("XERA_AUTH_RATE_LIMIT_PER_MIN", "30"))
WEEKEND_MODE = os.environ.get("XERA_WEEKEND_MODE", "always").strip().lower()
# Bind each username to the custom_id that first claimed it (set to 0 to disable).
STRICT_IDENTITY = os.environ.get("XERA_STRICT_IDENTITY", "1") != "0"

ACCESS_TTL = 2 * 3600
REFRESH_TTL = 7 * 24 * 3600

_DB_PATH = ""
_DEV_SECRET = ""
_JWT_SECRET = b""


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _b64url_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_json(obj) -> str:
    return _b64url_bytes(json.dumps(obj, separators=(",", ":")).encode())


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _db():
    """Connection that commits on success and ALWAYS closes."""
    conn = _conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# Client IP (spoof-resistant)
# --------------------------------------------------------------------------
def client_ip(req=None) -> str:
    """Real client IP. With N trusted proxies, the Nth entry from the RIGHT of
    X-Forwarded-For is the one your own proxy recorded; anything to its left
    is attacker-controlled."""
    req = req or request
    hops = TRUSTED_PROXY_HOPS
    if hops > 0:
        parts = [p.strip() for p in req.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return req.remote_addr or ""


# --------------------------------------------------------------------------
# JWTs (HS256, signed and verified)
# --------------------------------------------------------------------------
def make_jwt(user_id: str, username: str, refresh: bool = False) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "tid": secrets.token_hex(16),
        "uid": user_id,
        "usn": username,
        "vrs": {"clientUserAgent": "MetaQuest 1.61.2.0000_5edcbd98", "loginType": "meta_quest"},
        "exp": now + (REFRESH_TTL if refresh else ACCESS_TTL),
        "iat": now,
    }
    signing_input = f"{_b64url_json(header)}.{_b64url_json(payload)}"
    sig = hmac.new(_JWT_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_bytes(sig)}"


def verify_jwt(token: str):
    """Return the payload dict if the token is correctly signed and unexpired."""
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
        expected = hmac.new(_JWT_SECRET, f"{head_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def uid_from_request(req=None):
    """Drop-in replacement for extract_uid_from_token()."""
    req = req or request
    token = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token:
        return None
    payload = verify_jwt(token)
    return payload.get("uid") if payload else None


def _load_or_create_secret(key_path: str) -> bytes:
    env = os.environ.get("XERA_JWT_SECRET", "")
    if env:
        return env.encode()
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            data = f.read().strip()
            if data:
                return data
    data = secrets.token_hex(32).encode()
    with open(key_path, "wb") as f:
        f.write(data)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return data


# --------------------------------------------------------------------------
# Rate limiting (in-memory, per worker process)
# --------------------------------------------------------------------------
class _RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 20000:  # keep memory bounded
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True


_limiter = _RateLimiter()


# --------------------------------------------------------------------------
# Persistent bans
# --------------------------------------------------------------------------
def is_username_banned(username: str) -> bool:
    if not username:
        return False
    try:
        with _db() as c:
            return c.execute(
                "SELECT 1 FROM bans WHERE kind='username' AND value=?", (username.lower(),)
            ).fetchone() is not None
    except sqlite3.Error:
        return False


def is_ip_banned(ip: str) -> bool:
    if not ip:
        return False
    try:
        with _db() as c:
            return c.execute("SELECT 1 FROM bans WHERE kind='ip' AND value=?", (ip,)).fetchone() is not None
    except sqlite3.Error:
        return False


# --------------------------------------------------------------------------
# Username ownership
# --------------------------------------------------------------------------
def identity_allowed(username: str, custom_id: str) -> bool:
    """True if `custom_id` may log in as `username`.

    The client tells us its username (the Meta name) but nothing here verifies
    that with Meta, so on its own anyone could send username=<owner>. Instead
    the first custom_id to use a name owns it. Case-insensitive, because the
    owner/dev checks in backend.py are case-insensitive too (so "juelzirons"
    would otherwise get OWNER powers on a brand-new account)."""
    if not STRICT_IDENTITY:
        return True
    try:
        with _db() as c:
            rows = c.execute("SELECT custom_id FROM users WHERE username = ? COLLATE NOCASE",
                             (username,)).fetchall()
    except sqlite3.Error:
        return False  # fail closed
    if not rows:
        return True  # unclaimed name
    supplied = (custom_id or "").encode()
    for r in rows:
        stored = r["custom_id"] or ""
        if stored.startswith("released:") or hmac.compare_digest(stored.encode(), supplied):
            return True
    return False


# --------------------------------------------------------------------------
# Weekend mode
# --------------------------------------------------------------------------
def weekend_active(tz=None) -> bool:
    if WEEKEND_MODE == "off":
        return False
    if WEEKEND_MODE == "auto":
        return datetime.now(tz or timezone.utc).weekday() >= 5
    return True  # "always"


# --------------------------------------------------------------------------
# Blueprint: health, admin, friends
# --------------------------------------------------------------------------
bp = Blueprint("xera_extras", __name__)


def make_admin_token() -> str:
    """Short-lived (8h) admin session token for the admin website."""
    now = int(time.time())
    signing_input = f"{_b64url_json({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url_json({'role': 'admin', 'iat': now, 'exp': now + 8 * 3600})}"
    sig = hmac.new(_JWT_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_bytes(sig)}"


def _admin_ok() -> bool:
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if token:
        payload = verify_jwt(token)
        if payload and payload.get("role") == "admin":
            return True
    # An empty configured secret must NEVER authenticate (the original compared
    # "" == "" and let everyone in when the env var was unset).
    if not _DEV_SECRET:
        return False
    return hmac.compare_digest(request.headers.get("X-Dev-Secret", ""), _DEV_SECRET)


def _admin_only(fn):
    def wrapper(*a, **kw):
        if not _admin_ok():
            return jsonify({"error": "unauthorized"}), 401
        return fn(*a, **kw)

    wrapper.__name__ = fn.__name__
    return wrapper


def _json():
    body = request.get_json(force=True, silent=True)
    return body if isinstance(body, dict) else {}


@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": int(time.time())})


@bp.route("/admin/stats", methods=["GET"])
@_admin_only
def admin_stats():
    out = {}
    with _db() as c:
        for name, table in [("users", "users"), ("purchases", "purchases"), ("reports", "user_reports"),
                            ("privateRooms", "private_rooms"), ("friendEdges", "friends"), ("bans", "bans")]:
            try:
                out[name] = c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # table names are constants
            except sqlite3.Error:
                out[name] = None
        try:
            today = _iso_now()[:10]
            out["usersActiveToday"] = c.execute(
                "SELECT COUNT(*) FROM users WHERE update_time >= ?", (today,)
            ).fetchone()[0]
        except sqlite3.Error:
            out["usersActiveToday"] = None
    out["weekendMode"] = WEEKEND_MODE
    return jsonify(out)


@bp.route("/admin/ban", methods=["POST"])
@_admin_only
def admin_ban():
    body = _json()
    reason = str(body.get("reason", ""))[:200]
    added = []
    with _db() as c:
        for kind, key in (("username", "username"), ("ip", "ip")):
            val = str(body.get(key, "")).strip()
            if val:
                val = val.lower() if kind == "username" else val
                c.execute(
                    "INSERT OR REPLACE INTO bans (kind, value, reason, created_at) VALUES (?,?,?,?)",
                    (kind, val, reason, int(time.time())),
                )
                added.append({kind: val})
    if not added:
        return jsonify({"error": "provide username and/or ip"}), 400
    return jsonify({"ok": True, "banned": added})


@bp.route("/admin/unban", methods=["POST"])
@_admin_only
def admin_unban():
    body = _json()
    removed = 0
    with _db() as c:
        if body.get("username"):
            removed += c.execute("DELETE FROM bans WHERE kind='username' AND value=?",
                                 (str(body["username"]).strip().lower(),)).rowcount
        if body.get("ip"):
            removed += c.execute("DELETE FROM bans WHERE kind='ip' AND value=?",
                                 (str(body["ip"]).strip(),)).rowcount
    return jsonify({"ok": True, "removed": removed})


@bp.route("/admin/grant", methods=["POST"])
@_admin_only
def admin_grant():
    body = _json()
    username = str(body.get("username", "")).strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    try:
        soft, hard, rp = (int(body.get(k, 0)) for k in ("soft", "hard", "research"))
    except (TypeError, ValueError):
        return jsonify({"error": "soft/hard/research must be integers"}), 400
    with _db() as c:
        row = c.execute(
            "SELECT user_id FROM users WHERE username = ? COLLATE NOCASE ORDER BY update_time DESC LIMIT 1",
            (username,),
        ).fetchone()
        if not row:
            return jsonify({"error": "user not found"}), 404
        c.execute(
            "UPDATE wallets SET soft_currency = MAX(0, soft_currency + ?), hard_currency = MAX(0, hard_currency + ?), "
            "research_points = MAX(0, research_points + ?) WHERE user_id = ?",
            (soft, hard, rp, row["user_id"]),
        )
        w = c.execute("SELECT soft_currency, hard_currency, research_points FROM wallets WHERE user_id = ?",
                      (row["user_id"],)).fetchone()
    return jsonify({"ok": True, "wallet": dict(w) if w else None})


@bp.route("/admin/release_username", methods=["POST"])
@_admin_only
def admin_release_username():
    """For players who changed device / lost their ID: the next login with
    this username re-claims it. Use only after you've verified the person."""
    username = str(_json().get("username", "")).strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    with _db() as c:
        n = c.execute(
            "UPDATE users SET custom_id = 'released:' || hex(randomblob(8)) WHERE username = ? COLLATE NOCASE",
            (username,),
        ).rowcount
    return jsonify({"ok": True, "released": n})


@bp.route("/admin/reports", methods=["GET"])
@_admin_only
def admin_reports():
    limit = max(1, min(int(request.args.get("limit", 50) or 50), 500))
    with _db() as c:
        rows = c.execute(
            """SELECT r.id, r.reason, r.created_at,
                      ru.username AS reporter, tu.username AS target
               FROM user_reports r
               LEFT JOIN users ru ON ru.user_id = r.reporter_id
               LEFT JOIN users tu ON tu.user_id = r.target_user_id
               ORDER BY r.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return jsonify({"reports": [dict(r) for r in rows]})


# ---- Friends (Nakama-style states: 0 friends, 1 invite sent, 2 invite received, 3 blocked) ----
def _targets(conn, me):
    ids = list(request.args.getlist("ids"))
    names = list(request.args.getlist("usernames"))
    body = _json()
    for key, bucket in (("ids", ids), ("usernames", names)):
        val = body.get(key)
        if isinstance(val, list):
            bucket.extend(str(x) for x in val)
    found = set()
    for uid in ids:
        if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (uid,)).fetchone():
            found.add(uid)
    for name in names:
        row = conn.execute(
            "SELECT user_id FROM users WHERE username = ? COLLATE NOCASE ORDER BY update_time DESC LIMIT 1", (name,)
        ).fetchone()
        if row:
            found.add(row["user_id"])
    found.discard(me)
    return found


def _state(conn, a, b):
    row = conn.execute("SELECT state FROM friends WHERE user_id = ? AND friend_id = ?", (a, b)).fetchone()
    return row["state"] if row else None


def _set(conn, a, b, state):
    conn.execute(
        "INSERT INTO friends (user_id, friend_id, state, update_time) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id, friend_id) DO UPDATE SET state = excluded.state, update_time = excluded.update_time",
        (a, b, state, int(time.time())),
    )


def _add_friend(conn, me, other):
    if _state(conn, other, me) == 3 or _state(conn, me, other) == 3:
        return  # blocked either way: do nothing (and don't reveal it)
    mine, theirs = _state(conn, me, other), _state(conn, other, me)
    if mine == 2 or theirs == 1:  # they already invited me -> accept
        _set(conn, me, other, 0)
        _set(conn, other, me, 0)
    elif mine is None:
        _set(conn, me, other, 1)
        _set(conn, other, me, 2)


def _friend_json(row):
    return {
        "user": {
            "id": row["user_id"], "username": row["username"], "lang_tag": row["lang_tag"],
            "metadata": row["metadata"], "edge_count": 0,
            "create_time": row["create_time"], "update_time": row["update_time"],
        },
        "state": row["state"],
        "update_time": row["f_update"],
    }


@bp.route("/v2/friend", methods=["GET"])
@bp.route("/v2/friends", methods=["GET"])
def friends_list():
    me = uid_from_request()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    limit = max(1, min(int(request.args.get("limit", 100) or 100), 1000))
    state = request.args.get("state")
    sql = """SELECT u.*, f.state, f.update_time AS f_update
             FROM friends f JOIN users u ON u.user_id = f.friend_id
             WHERE f.user_id = ?"""
    params = [me]
    if state not in (None, ""):
        sql += " AND f.state = ?"
        params.append(int(state))
    sql += " ORDER BY f.update_time DESC LIMIT ?"
    params.append(limit)
    with _db() as c:
        rows = c.execute(sql, params).fetchall()
    return jsonify({"friends": [_friend_json(r) for r in rows], "cursor": ""})


@bp.route("/v2/friend", methods=["POST"])
def friends_add():
    me = uid_from_request()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    with _db() as c:
        for other in _targets(c, me):
            _add_friend(c, me, other)
    return jsonify({})


@bp.route("/v2/friend", methods=["DELETE"])
def friends_remove():
    me = uid_from_request()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    with _db() as c:
        for other in _targets(c, me):
            if _state(c, me, other) == 3:  # DELETE on a blocked user = unblock
                c.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (me, other))
            elif _state(c, other, me) != 3:
                c.execute("DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)",
                          (me, other, other, me))
    return jsonify({})


@bp.route("/v2/friend/block", methods=["POST"])
def friends_block():
    me = uid_from_request()
    if not me:
        return jsonify({"error": "unauthorized"}), 401
    with _db() as c:
        for other in _targets(c, me):
            _set(c, me, other, 3)
            if _state(c, other, me) != 3:
                c.execute("DELETE FROM friends WHERE user_id = ? AND friend_id = ?", (other, me))
    return jsonify({})


# --------------------------------------------------------------------------
# install()
# --------------------------------------------------------------------------
def install(app, db_path: str, dev_secret: str = "", jwt_key_path: str = None):
    """Call once, after init_db() in backend.py."""
    global _DB_PATH, _DEV_SECRET, _JWT_SECRET
    _DB_PATH = db_path
    _DEV_SECRET = dev_secret or ""
    _JWT_SECRET = _load_or_create_secret(jwt_key_path or os.path.join(os.path.dirname(db_path), "jwt_secret.key"))

    if not logging.getLogger().handlers:
        logging.basicConfig(level=os.environ.get("XERA_LOG_LEVEL", "INFO"),
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    with _db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS bans (
                kind TEXT NOT NULL, value TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL, PRIMARY KEY (kind, value)
            );
            CREATE TABLE IF NOT EXISTS friends (
                user_id TEXT NOT NULL, friend_id TEXT NOT NULL, state INTEGER NOT NULL,
                update_time INTEGER NOT NULL, PRIMARY KEY (user_id, friend_id)
            );
            CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id, state);
        """)

    @app.before_request
    def _xera_gate():
        g._xera_t0 = time.perf_counter()
        g.request_id = uuid.uuid4().hex[:12]
        if request.path == "/health":
            return None
        ip = client_ip()
        if is_ip_banned(ip):
            return jsonify({"error": "banned", "message": "You have been IP banned from Xera Company."}), 403
        is_auth = request.path.startswith("/v2/account/authenticate") or request.path == "/admin/login"
        limit = AUTH_RATE_LIMIT_PER_MIN if is_auth else RATE_LIMIT_PER_MIN
        if not _limiter.allow(f"{'auth' if is_auth else 'all'}:{ip}", limit):
            resp = jsonify({"error": "rate_limited", "message": "Too many requests, slow down."})
            resp.headers["Retry-After"] = "30"
            return resp, 429
        return None

    @app.after_request
    def _xera_log(resp):
        resp.headers["X-Request-ID"] = g.get("request_id", "")
        if request.path != "/health":
            ms = (time.perf_counter() - g.get("_xera_t0", time.perf_counter())) * 1000
            log.info("%s %s -> %s (%.0fms) ip=%s rid=%s", request.method, request.path,
                     resp.status_code, ms, client_ip(), g.get("request_id", ""))
        return resp

    app.register_blueprint(bp)
    log.info("xera_extras installed (proxy hops=%s, weekend=%s)", TRUSTED_PROXY_HOPS, WEEKEND_MODE)


# --------------------------------------------------------------------------
# CLI: python xera_extras.py backup [dest_dir]
# --------------------------------------------------------------------------
def backup(db_path: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f"Data-{time.strftime('%Y%m%d-%H%M%S')}.db")
    src, dst = sqlite3.connect(db_path), sqlite3.connect(dest)
    with dst:
        src.backup(dst)  # safe while the server is running
    src.close()
    dst.close()
    return dest


if __name__ == "__main__":
    data = os.environ.get("XERA_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) >= 2 and sys.argv[1] == "backup":
        print("Backup written to", backup(os.path.join(data, "Data.db"),
                                          sys.argv[2] if len(sys.argv) > 2 else os.path.join(data, "backups")))
    else:
        print(__doc__)
