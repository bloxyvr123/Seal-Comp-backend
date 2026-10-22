"""
xera_admin.py - admin website API for Xera Company Backend.
Needs xera_extras.py. Serves the panel at /admin-panel (file: admin_panel.html).
Wiring: see PATCHES.md step 9.
"""
import json
import hmac
import os
import secrets
import time

from flask import Blueprint, jsonify, request, send_file

import xera_extras as E

bp = Blueprint("xera_admin", __name__)
_cache = (0, {})


def unlock_all_enabled():
    """backend.py gives EVERY player the whole catalog on login. Set
    XERA_UNLOCK_ALL_AVATAR=0 so granted/revoked cosmetics actually matter."""
    return os.environ.get("XERA_UNLOCK_ALL_AVATAR", "1") != "0"


def catalog():
    global _cache
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "econ_avatar_items.json")
    try:
        m = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache[0] != m:
        with open(path) as f:
            _cache = (m, {i["id"]: i for i in json.load(f) if isinstance(i, dict) and "id" in i})
    return _cache[1]


def category(item_id):
    p = item_id.split("_")
    return "_".join(p[:2]) if p[0] in ("bp", "acc") and len(p) > 2 else p[0]


def audit(c, action, detail=""):
    c.execute("INSERT INTO admin_audit (ts, ip, action, detail) VALUES (?,?,?,?)",
              (int(time.time()), E.client_ip(), action, str(detail)[:500]))


def _find(c, ref):
    ref = str(ref).strip()
    return c.execute("SELECT * FROM users WHERE user_id = ? OR username = ? COLLATE NOCASE "
                     "ORDER BY update_time DESC LIMIT 1", (ref, ref)).fetchone()


def _inv(c, uid):
    r = c.execute("SELECT value FROM storage WHERE user_id=? AND collection='user_inventory' AND key='avatar'",
                  (uid,)).fetchone()
    try:
        return list(json.loads(r["value"]).get("items", [])) if r else []
    except Exception:
        return []


def _save(c, uid, items):
    now = E._iso_now()
    c.execute(
        "INSERT INTO storage (user_id,collection,key,value,version,permission_read,permission_write,create_time,update_time)"
        " VALUES (?,?,?,?,?,1,1,?,?) ON CONFLICT(user_id,collection,key) DO UPDATE SET"
        " value=excluded.value, version=excluded.version, update_time=excluded.update_time",
        (uid, "user_inventory", "avatar", json.dumps({"items": items}), secrets.token_hex(16), now, now))


@bp.route("/admin-panel")
def panel():
    r = send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin_panel.html"))
    r.headers["Cache-Control"] = "no-store"
    r.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    return r


@bp.route("/admin/login", methods=["POST"])
def login():
    given = str(E._json().get("secret", ""))
    if not E._DEV_SECRET or not hmac.compare_digest(given, E._DEV_SECRET):
        return jsonify({"error": "wrong secret"}), 401
    with E._db() as c:
        audit(c, "login")
    return jsonify({"token": E.make_admin_token()})


@bp.route("/admin/users")
@E._admin_only
def users():
    q = request.args.get("q", "").strip()
    with E._db() as c:
        rows = c.execute(
            "SELECT u.user_id, u.username, u.ip, u.create_time, u.update_time, w.soft_currency AS soft,"
            " w.hard_currency AS hard, w.research_points AS research FROM users u LEFT JOIN wallets w USING(user_id)"
            " WHERE u.username LIKE ? OR u.user_id = ? OR u.ip = ? ORDER BY u.update_time DESC LIMIT 50",
            (f"%{q}%", q, q)).fetchall()
    return jsonify({"users": [dict(r) for r in rows]})


@bp.route("/admin/users/<uid>")
@E._admin_only
def user_detail(uid):
    with E._db() as c:
        u = _find(c, uid)
        if not u:
            return jsonify({"error": "user not found"}), 404
        w = c.execute("SELECT soft_currency AS soft, hard_currency AS hard, research_points AS research"
                      " FROM wallets WHERE user_id = ?", (u["user_id"],)).fetchone()
        banned = c.execute("SELECT 1 FROM bans WHERE kind='username' AND value=?", (u["username"].lower(),)).fetchone()
        reports = c.execute("SELECT COUNT(*) FROM user_reports WHERE target_user_id=?", (u["user_id"],)).fetchone()[0]
        return jsonify({"user": {k: u[k] for k in ("user_id", "username", "ip", "create_time", "update_time")},
                        "wallet": dict(w) if w else {}, "items": _inv(c, u["user_id"]),
                        "banned": bool(banned), "reportsAgainst": reports})


@bp.route("/admin/cosmetics")
@E._admin_only
def cosmetics():
    with E._db() as c:
        ov = {r["item_id"]: r["price"] for r in c.execute("SELECT * FROM price_overrides")}
    return jsonify({"unlockAllOnLogin": unlock_all_enabled(),
                    "items": [{"id": i, "category": category(i), "price": ov.get(i, d.get("hardPrice", 0)),
                               "custom": i in ov} for i, d in sorted(catalog().items())]})


@bp.route("/admin/cosmetics/<action>", methods=["POST"])
@E._admin_only
def cosmetics_change(action):
    if action not in ("grant", "revoke"):
        return jsonify({"error": "unknown action"}), 404
    b = E._json()
    items = [str(i).strip() for i in b.get("items", []) if str(i).strip()]
    cat = catalog()
    bad = [i for i in items if cat and i not in cat]
    if not items or bad:
        return jsonify({"error": "no items, or unknown item ids", "unknown": bad}), 400
    with E._db() as c:
        if b.get("all"):
            uids = [r[0] for r in c.execute("SELECT user_id FROM users")]
        else:
            u = _find(c, b.get("user", ""))
            if not u:
                return jsonify({"error": "user not found"}), 404
            uids = [u["user_id"]]
        for uid in uids:
            cur = _inv(c, uid)
            _save(c, uid, cur + [i for i in items if i not in cur] if action == "grant"
                  else [i for i in cur if i not in items])
        audit(c, f"cosmetics.{action}", f"{'ALL' if b.get('all') else b.get('user')}: {', '.join(items)[:300]}")
    return jsonify({"ok": True, "users": len(uids)})


@bp.route("/admin/promos", methods=["GET", "POST"])
@E._admin_only
def promos():
    with E._db() as c:
        if request.method == "POST":
            b = E._json()
            code = str(b.get("code", "")).strip().upper()
            if not code:
                return jsonify({"error": "code required"}), 400
            try:
                soft, hard, rp, mx = (int(b.get(k, d)) for k, d in
                                      (("soft", 0), ("hard", 0), ("research", 0), ("max", -1)))
            except (TypeError, ValueError):
                return jsonify({"error": "numbers must be integers"}), 400
            items = [str(i).strip() for i in b.get("items", []) if str(i).strip()]
            c.execute(
                "INSERT INTO promo_codes (code, reward_soft, reward_hard, reward_research, reward_avatar_items,"
                " max_redemptions, active) VALUES (?,?,?,?,?,?,1) ON CONFLICT(code) DO UPDATE SET"
                " reward_soft=excluded.reward_soft, reward_hard=excluded.reward_hard,"
                " reward_research=excluded.reward_research, reward_avatar_items=excluded.reward_avatar_items,"
                " max_redemptions=excluded.max_redemptions, active=1",
                (code, soft, hard, rp, json.dumps(items), mx))
            audit(c, "promo.save", code)
            return jsonify({"ok": True})
        rows = c.execute("SELECT * FROM promo_codes ORDER BY code").fetchall()
    return jsonify({"promos": [dict(r) for r in rows]})


@bp.route("/admin/promos/<code>", methods=["DELETE"])
@E._admin_only
def promo_delete(code):
    with E._db() as c:
        c.execute("DELETE FROM promo_codes WHERE code = ?", (code.upper(),))
        audit(c, "promo.delete", code)
    return jsonify({"ok": True})


@bp.route("/admin/bans")
@E._admin_only
def bans():
    with E._db() as c:
        return jsonify({"bans": [dict(r) for r in c.execute("SELECT * FROM bans ORDER BY created_at DESC")]})


@bp.route("/admin/audit")
@E._admin_only
def audit_log():
    with E._db() as c:
        return jsonify({"audit": [dict(r) for r in c.execute("SELECT * FROM admin_audit ORDER BY id DESC LIMIT 200")]})


def price_override(item_id):
    """Custom hard-currency price set in the panel, or None. Used by backend.py."""
    try:
        with E._db() as c:
            r = c.execute("SELECT price FROM price_overrides WHERE item_id=?", (item_id,)).fetchone()
        return r["price"] if r else None
    except Exception:
        return None


@bp.route("/admin/cosmetics/price", methods=["POST"])
@E._admin_only
def set_price():
    b = E._json()
    item, cat = str(b.get("item", "")), catalog()
    if cat and item not in cat:
        return jsonify({"error": "unknown item"}), 404
    with E._db() as c:
        if b.get("price") is None:
            c.execute("DELETE FROM price_overrides WHERE item_id=?", (item,))
        else:
            try:
                p = int(b["price"])
            except (TypeError, ValueError):
                return jsonify({"error": "price must be a whole number"}), 400
            if p < 0:
                return jsonify({"error": "price cannot be negative"}), 400
            c.execute("INSERT INTO price_overrides (item_id, price) VALUES (?,?) "
                      "ON CONFLICT(item_id) DO UPDATE SET price=excluded.price", (item, p))
        audit(c, "price.set", f"{item} -> {b.get('price')}")
    return jsonify({"ok": True})


@bp.route("/admin/bundles", methods=["GET", "POST"])
@E._admin_only
def bundles():
    with E._db() as c:
        if request.method == "POST":
            b = E._json()
            name = str(b.get("name", "")).strip()[:60]
            items = [str(i).strip() for i in b.get("items", []) if str(i).strip()]
            cat = catalog()
            bad = [i for i in items if cat and i not in cat]
            if not name or not items or bad:
                return jsonify({"error": "a name and valid item ids are required", "unknown": bad}), 400
            c.execute("INSERT INTO bundles (name, items, created_at) VALUES (?,?,?) "
                      "ON CONFLICT(name) DO UPDATE SET items=excluded.items", (name, json.dumps(items), int(time.time())))
            audit(c, "bundle.save", name)
            return jsonify({"ok": True})
        rows = c.execute("SELECT * FROM bundles ORDER BY name").fetchall()
    return jsonify({"bundles": [{"name": r["name"], "items": json.loads(r["items"])} for r in rows]})


@bp.route("/admin/bundles/<name>", methods=["DELETE"])
@E._admin_only
def bundle_delete(name):
    with E._db() as c:
        c.execute("DELETE FROM bundles WHERE name = ?", (name,))
        audit(c, "bundle.delete", name)
    return jsonify({"ok": True})


@bp.route("/admin/rooms")
@E._admin_only
def rooms():
    q = f"%{request.args.get('q', '').strip()}%"
    with E._db() as c:
        rows = c.execute("SELECT r.*, u.username AS owner_name FROM private_rooms r LEFT JOIN users u ON u.user_id = r.owner"
                         " WHERE r.code LIKE ? OR u.username LIKE ? ORDER BY r.expires_at DESC LIMIT 100", (q, q)).fetchall()
    return jsonify({"rooms": [{"code": r["code"], "owner": r["owner_name"] or r["owner"], "expiresAt": r["expires_at"],
                               "members": len(json.loads(r["members"])), "banned": len(json.loads(r["banned_users"]))}
                              for r in rows]})


@bp.route("/admin/rooms/<code>/extend", methods=["POST"])
@E._admin_only
def room_extend(code):
    try:
        days = max(1, min(int(E._json().get("days", 30)), 365))
    except (TypeError, ValueError):
        return jsonify({"error": "days must be a whole number"}), 400
    with E._db() as c:
        n = c.execute("UPDATE private_rooms SET expires_at = MAX(expires_at, ?) + ? WHERE code = ?",
                      (int(time.time()), days * 86400, code)).rowcount
        audit(c, "room.extend", f"{code} +{days}d")
    return jsonify({"ok": bool(n)}), (200 if n else 404)


@bp.route("/admin/rooms/<code>", methods=["DELETE"])
@E._admin_only
def room_delete(code):
    with E._db() as c:
        c.execute("DELETE FROM private_rooms WHERE code = ?", (code,))
        audit(c, "room.delete", code)
    return jsonify({"ok": True})


def install(app):
    """Call after xera_extras.install(...)."""
    with E._db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER,
                ip TEXT, action TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS bundles (name TEXT PRIMARY KEY, items TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS price_overrides (item_id TEXT PRIMARY KEY, price INTEGER NOT NULL);
        """)
    app.register_blueprint(bp)
