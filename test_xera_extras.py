import importlib
import sqlite3

import pytest
from flask import Flask, jsonify

import xera_extras as x

BASE_SCHEMA = """
CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT, custom_id TEXT, ip TEXT DEFAULT '',
    lang_tag TEXT DEFAULT 'en', metadata TEXT DEFAULT '{}', create_time TEXT, update_time TEXT);
CREATE TABLE wallets (user_id TEXT PRIMARY KEY, soft_currency INT DEFAULT 100,
    hard_currency INT DEFAULT 5000, research_points INT DEFAULT 10);
CREATE TABLE user_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id TEXT,
    target_user_id TEXT, reason TEXT, created_at INT);
CREATE TABLE purchases (id INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE private_rooms (code TEXT PRIMARY KEY);
"""

SECRET = "test-admin-secret"


def make_client(tmp_path, dev_secret=SECRET, hops=1):
    importlib.reload(x)
    x.TRUSTED_PROXY_HOPS = hops
    db = str(tmp_path / "t.db")
    conn = sqlite3.connect(db)
    conn.executescript(BASE_SCHEMA)
    for uid, name in (("u-alice", "Alice"), ("u-bob", "Bob"), ("u-cara", "Cara")):
        conn.execute("INSERT INTO users (user_id, username, custom_id, create_time, update_time) VALUES (?,?,?,?,?)",
                     (uid, name, uid, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))
        conn.execute("INSERT INTO wallets (user_id) VALUES (?)", (uid,))
    conn.commit()
    conn.close()

    app = Flask(__name__)

    @app.route("/ping")
    def ping():
        return jsonify({"uid": x.uid_from_request(), "ip": x.client_ip()})

    @app.route("/v2/account/authenticate/custom", methods=["POST"])
    def fake_auth():
        return jsonify({})

    x.install(app, db, dev_secret, jwt_key_path=str(tmp_path / "jwt.key"))
    return app.test_client(), db


def auth(uid):
    return {"Authorization": f"Bearer {x.make_jwt(uid, uid)}"}


# ---------------- JWT ----------------
def test_valid_token_resolves_uid(tmp_path):
    c, _ = make_client(tmp_path)
    assert c.get("/ping", headers=auth("u-alice")).get_json()["uid"] == "u-alice"


def test_forged_unsigned_token_rejected(tmp_path):
    c, _ = make_client(tmp_path)
    forged = f"{x._b64url_json({'alg': 'none'})}.{x._b64url_json({'uid': 'u-alice', 'exp': 9999999999})}.abc"
    assert c.get("/ping", headers={"Authorization": f"Bearer {forged}"}).get_json()["uid"] is None


def test_tampered_payload_rejected(tmp_path):
    c, _ = make_client(tmp_path)
    h, _p, s = x.make_jwt("u-alice", "Alice").split(".")
    evil = x._b64url_json({"uid": "u-bob", "exp": 9999999999})
    assert c.get("/ping", headers={"Authorization": f"Bearer {h}.{evil}.{s}"}).get_json()["uid"] is None


def test_expired_token_rejected(tmp_path):
    c, _ = make_client(tmp_path)
    x.ACCESS_TTL = -10
    tok = x.make_jwt("u-alice", "Alice")
    assert c.get("/ping", headers={"Authorization": f"Bearer {tok}"}).get_json()["uid"] is None


# ---------------- IP handling ----------------
def test_spoofed_xff_left_entry_ignored(tmp_path):
    c, _ = make_client(tmp_path, hops=1)
    # attacker prepends 127.0.0.1; our proxy appended the real IP on the right
    r = c.get("/ping", headers={"X-Forwarded-For": "127.0.0.1, 203.0.113.9"})
    assert r.get_json()["ip"] == "203.0.113.9"


def test_no_proxy_ignores_xff_entirely(tmp_path):
    c, _ = make_client(tmp_path, hops=0)
    r = c.get("/ping", headers={"X-Forwarded-For": "9.9.9.9"})
    assert r.get_json()["ip"] != "9.9.9.9"  # falls back to the socket address


# ---------------- Admin ----------------
def test_admin_requires_secret(tmp_path):
    c, _ = make_client(tmp_path)
    assert c.get("/admin/stats").status_code == 401
    assert c.get("/admin/stats", headers={"X-Dev-Secret": "wrong"}).status_code == 401
    assert c.get("/admin/stats", headers={"X-Dev-Secret": SECRET}).status_code == 200


def test_empty_secret_never_authenticates(tmp_path):
    c, _ = make_client(tmp_path, dev_secret="")
    assert c.get("/admin/stats", headers={"X-Dev-Secret": ""}).status_code == 401
    assert c.get("/admin/stats").status_code == 401


def test_grant_and_reports(tmp_path):
    c, db = make_client(tmp_path)
    h = {"X-Dev-Secret": SECRET}
    r = c.post("/admin/grant", json={"username": "alice", "hard": 250, "soft": -50}, headers=h)
    assert r.status_code == 200 and r.get_json()["wallet"]["hard_currency"] == 5250
    assert r.get_json()["wallet"]["soft_currency"] == 50
    assert c.post("/admin/grant", json={"username": "ghost"}, headers=h).status_code == 404
    sqlite3.connect(db).execute("INSERT INTO user_reports (reporter_id,target_user_id,reason,created_at) VALUES ('u-alice','u-bob','spam',1)").connection.commit()
    reps = c.get("/admin/reports", headers=h).get_json()["reports"]
    assert reps[0]["reporter"] == "Alice" and reps[0]["target"] == "Bob"


# ---------------- Bans ----------------
def test_ip_ban_and_unban(tmp_path):
    c, _ = make_client(tmp_path)
    h = {"X-Dev-Secret": SECRET}
    ip = {"X-Forwarded-For": "198.51.100.7"}
    assert c.get("/ping", headers=ip).status_code == 200
    assert c.post("/admin/ban", json={"ip": "198.51.100.7", "reason": "grief"}, headers=h).status_code == 200
    assert c.get("/ping", headers=ip).status_code == 403
    c.post("/admin/unban", json={"ip": "198.51.100.7"}, headers=h)
    assert c.get("/ping", headers=ip).status_code == 200


def test_username_ban_is_case_insensitive(tmp_path):
    c, _ = make_client(tmp_path)
    c.post("/admin/ban", json={"username": "Bob"}, headers={"X-Dev-Secret": SECRET})
    assert x.is_username_banned("bOb") and not x.is_username_banned("alice")


# ---------------- Rate limit ----------------
def test_auth_rate_limit(tmp_path):
    c, _ = make_client(tmp_path)
    x.AUTH_RATE_LIMIT_PER_MIN = 3
    codes = [c.post("/v2/account/authenticate/custom", headers={"X-Forwarded-For": "192.0.2.1"}).status_code
             for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_health_not_rate_limited_or_logged(tmp_path):
    c, _ = make_client(tmp_path)
    assert all(c.get("/health").status_code == 200 for _ in range(50))


# ---------------- Friends ----------------
def states(c, uid, **q):
    r = c.get("/v2/friend", headers=auth(uid), query_string=q)
    return {f["user"]["username"]: f["state"] for f in r.get_json()["friends"]}


def test_friend_request_accept_remove(tmp_path):
    c, _ = make_client(tmp_path)
    c.post("/v2/friend?usernames=Bob", headers=auth("u-alice"))
    assert states(c, "u-alice") == {"Bob": 1}      # invite sent
    assert states(c, "u-bob") == {"Alice": 2}      # invite received
    c.post("/v2/friend?ids=u-alice", headers=auth("u-bob"))
    assert states(c, "u-alice") == {"Bob": 0} and states(c, "u-bob") == {"Alice": 0}
    c.delete("/v2/friend?usernames=Alice", headers=auth("u-bob"))
    assert states(c, "u-alice") == {} and states(c, "u-bob") == {}


def test_block_prevents_requests_and_unblocks(tmp_path):
    c, _ = make_client(tmp_path)
    c.post("/v2/friend/block?usernames=Alice", headers=auth("u-bob"))
    c.post("/v2/friend?usernames=Bob", headers=auth("u-alice"))   # silently ignored
    assert states(c, "u-alice") == {}
    assert states(c, "u-bob") == {"Alice": 3}
    c.delete("/v2/friend?usernames=Alice", headers=auth("u-bob"))  # unblock
    assert states(c, "u-bob") == {}


def test_cannot_friend_self_and_state_filter(tmp_path):
    c, _ = make_client(tmp_path)
    c.post("/v2/friend?usernames=Alice", headers=auth("u-alice"))
    assert states(c, "u-alice") == {}
    c.post("/v2/friend?usernames=Bob&usernames=Cara", headers=auth("u-alice"))
    assert set(states(c, "u-alice", state=1)) == {"Bob", "Cara"}
    assert states(c, "u-alice", state=0) == {}


def test_friends_require_auth(tmp_path):
    c, _ = make_client(tmp_path)
    assert c.get("/v2/friend").status_code == 401
    assert c.post("/v2/friend?usernames=Bob").status_code == 401


# ---------------- Weekend + backup ----------------
def test_weekend_modes(tmp_path, monkeypatch):
    make_client(tmp_path)
    x.WEEKEND_MODE = "always"; assert x.weekend_active() is True
    x.WEEKEND_MODE = "off";    assert x.weekend_active() is False
    x.WEEKEND_MODE = "auto";   assert x.weekend_active() in (True, False)


def test_backup_creates_valid_copy(tmp_path):
    _, db = make_client(tmp_path)
    dest = x.backup(db, str(tmp_path / "bk"))
    assert sqlite3.connect(dest).execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3


# ---------------- Username ownership ----------------
def test_username_bound_to_first_custom_id(tmp_path):
    make_client(tmp_path)
    x.STRICT_IDENTITY = True
    assert x.identity_allowed("Alice", "u-alice")           # owner
    assert x.identity_allowed("alice", "u-alice")           # case-insensitive
    assert not x.identity_allowed("Alice", "attacker-id")   # impostor
    assert not x.identity_allowed("ALICE", "")              # no id at all
    assert x.identity_allowed("BrandNewName", "anything")   # unclaimed


def test_case_variant_cannot_claim_existing_name(tmp_path):
    make_client(tmp_path)
    x.STRICT_IDENTITY = True
    assert not x.identity_allowed("bOb", "not-bobs-id")


def test_release_username_lets_new_device_reclaim(tmp_path):
    c, _ = make_client(tmp_path)
    x.STRICT_IDENTITY = True
    assert not x.identity_allowed("Bob", "new-phone")
    assert c.post("/admin/release_username", json={"username": "bob"}).status_code == 401
    r = c.post("/admin/release_username", json={"username": "bob"}, headers={"X-Dev-Secret": SECRET})
    assert r.get_json()["released"] == 1
    assert x.identity_allowed("Bob", "new-phone")


def test_strict_identity_can_be_disabled(tmp_path):
    make_client(tmp_path)
    x.STRICT_IDENTITY = False
    assert x.identity_allowed("Alice", "attacker-id")
