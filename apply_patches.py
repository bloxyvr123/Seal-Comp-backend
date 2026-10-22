#!/usr/bin/env python3
"""
apply_patches.py - applies every edit from PATCHES.md to your backend.py.

    python apply_patches.py                 # patches ./backend.py
    python apply_patches.py path/backend.py
    python apply_patches.py --dry-run       # shows the report, changes nothing

Safe by design:
  * writes backend.py.bak first
  * every patch must match its anchor text exactly the expected number of times,
    otherwise that patch is SKIPPED and reported (apply it by hand from PATCHES.md)
  * the result must still parse as valid Python, or nothing is written
  * running it twice does nothing the second time
"""
import ast
import re
import shutil
import sys

RX = re.M | re.S

NEW_JWT = '''def make_jwt(user_id, username):
    return xera_extras.make_jwt(user_id, username)

'''
NEW_EXTRACT = '''def extract_uid_from_token():
    return xera_extras.uid_from_request()

'''
NEW_IP = '''def get_client_ip():
    return xera_extras.client_ip()

'''
IDENTITY_BLOCK = '''    if xera_extras.is_username_banned(username):
        return None, jsonify({"error": "banned", "message": BAN_MESSAGE}), 403
    if not xera_extras.identity_allowed(username, custom_id):
        return None, jsonify({"error": "username_taken",
                              "message": "That username belongs to another device."}), 403

    user_id = get_or_create_user(custom_id, username)'''
FRIEND_STUBS = (r'(?:@app\.route\("/v2/friends?(?:/block)?"[^\n]*\n)+'
                r'def (?:list_friends|add_friends|manage_friends)\(\):\n[ \t]+return [^\n]*\n\n?')

# (id, title, kind, pattern/old, replacement, expected_count, requires, required)
PATCHES = [
    ("1a", "import the add-on modules", "rx", r"^import pytz[ \t]*$",
     "import pytz\nimport xera_extras\nimport xera_admin", 1, None, True),
    ("11a", "data directory + discord DB path", "rx", r"^DISCORD_DEV_DB_PATH[ \t]*=.*$",
     'DATA_DIR                = os.environ.get("XERA_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))\n'
     'DISCORD_DEV_DB_PATH     = os.path.join(DATA_DIR, "discord_devs.db")', 1, None, False),
    ("11b", "main database path uses the data directory", "rx", r"^DB_PATH[ \t]*=.*$",
     'DB_PATH         = os.path.join(DATA_DIR, "Data.db")', 1, "11a", False),
    ("1b", "install the add-ons after init_db()", "rx", r"^init_db\(\)[ \t]*$",
     "init_db()\n\nxera_extras.install(app, DB_PATH, DISCORD_DEV_SECRET)\nxera_admin.install(app)", 1, None, True),
    ("2a", "signed tokens: make_jwt", "rx", r"^def make_jwt\(user_id, username\):.*?(?=^def extract_uid_from_token)",
     NEW_JWT, 1, None, False),
    ("2b", "signed tokens: extract_uid_from_token", "rx", r"^def extract_uid_from_token\(\):.*?(?=^def get_client_ip)",
     NEW_EXTRACT, 1, None, False),
    ("3a", "safe client IP: get_client_ip", "rx", r"^def get_client_ip\(\):.*?(?=^def get_or_create_user)",
     NEW_IP, 1, None, False),
    ("3b", "safe client IP: webhook + IP-ban middleware", "lit",
     'request.headers.get("X-Forwarded-For", request.remote_addr)', "get_client_ip()", 2, "3a", False),
    ("2c", "long-lived refresh token (login)", "rx", r"refresh\s*=\s*make_jwt\(user_id, display\)",
     "refresh = xera_extras.make_jwt(user_id, display, refresh=True)", 1, "2a", False),
    ("2d", "long-lived refresh token (session refresh)", "lit",
     '"refresh_token": make_jwt(user_id, display)',
     '"refresh_token": xera_extras.make_jwt(user_id, display, refresh=True)', 1, "2a", False),
    ("4+8", "persistent bans + username ownership", "lit",
     "    user_id = get_or_create_user(custom_id, username)", IDENTITY_BLOCK, 1, None, False),
    ("9a", "optional unlock-all-cosmetics on login", "lit",
     "\n    unlock_all_avatar_items(user_id)\n",
     "\n    if xera_admin.unlock_all_enabled():\n        unlock_all_avatar_items(user_id)\n", 1, None, False),
    ("5", "weekend mode switch", "rx", r"^def is_weekend_est\(\):\n    return True",
     "def is_weekend_est():\n    return xera_extras.weekend_active(EST_TIMEZONE)", 1, None, False),
    ("6", "remove the empty friends stubs", "rx", FRIEND_STUBS, "", 3, None, False),
    ("7a", "admin endpoints: empty secret never authenticates", "lit",
     'if request.headers.get("X-Dev-Secret", "") != DISCORD_DEV_SECRET:',
     'if not DISCORD_DEV_SECRET or request.headers.get("X-Dev-Secret", "") != DISCORD_DEV_SECRET:', 2, None, False),
    ("7b", "storage listing only exposes public-read objects", "lit",
     '"SELECT * FROM storage WHERE user_id = ? AND collection = ?", (uid_param, collection)',
     '"SELECT * FROM storage WHERE user_id = ? AND collection = ? AND permission_read = 2", (uid_param, collection)',
     1, None, False),
    ("7c", "/debug requires admin", "lit", "def debug_endpoint():\n",
     'def debug_endpoint():\n    if not xera_extras._admin_ok():\n        return jsonify({"error": "unauthorized"}), 401\n',
     1, None, False),
    ("7d", "never run the Werkzeug debugger on 0.0.0.0", "lit",
     'app.run(debug=True, host="0.0.0.0", port=5000)', 'app.run(debug=False, host="127.0.0.1", port=5000)', 1, None, False),
    ("10", "custom cosmetic prices from the admin panel", "lit", "def get_avatar_item_price(item_id):\n",
     "def get_avatar_item_price(item_id):\n    custom = xera_admin.price_override(item_id)\n"
     "    if custom is not None:\n        return custom\n", 1, None, False),
]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    path = args[0] if args else "backend.py"
    try:
        raw = open(path, newline="").read()
    except OSError as e:
        sys.exit(f"Cannot read {path}: {e}")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    if "xera_extras" in text:
        sys.exit("This file already mentions xera_extras, so it looks patched. Nothing to do.")

    done, report = set(), []
    for pid, title, kind, old, new, count, needs, required in PATCHES:
        if needs and needs not in done:
            report.append((pid, title, f"skipped: needs patch {needs} first"))
            continue
        if kind == "lit":
            n = text.count(old)
            ok = n == count
            if ok:
                text = text.replace(old, new)
        else:
            flags = RX if ".*?" in old else re.M
            patched, n = re.subn(old, lambda m, r=new: r, text, flags=flags)
            ok = n == count
            if ok:
                text = patched
        if ok:
            done.add(pid)
            report.append((pid, title, "applied"))
        else:
            report.append((pid, title, f"SKIPPED: found {n} match(es), expected {count}. Apply by hand (PATCHES.md)"))
            if required:
                for r in report:
                    print(f"  [{r[0]:>3}] {r[2]:<10} {r[1]}" if r[2] == "applied" else f"  [{r[0]:>3}] {r[2]}  - {r[1]}")
                sys.exit(f"\nRequired patch {pid} failed, so nothing was written.")

    try:
        ast.parse(text)
    except SyntaxError as e:
        sys.exit(f"The patched file would not be valid Python ({e}). Nothing written. Please send me this message.")

    print(f"Patch report for {path}:")
    for pid, title, status in report:
        print(f"  [{pid:>3}] {status:<8} {title}" if status == "applied" else f"  [{pid:>3}] {status}  - {title}")
    skipped = [r for r in report if r[2] != "applied"]
    if dry:
        print("\nDry run: nothing written.")
        return
    shutil.copy(path, path + ".bak")
    with open(path, "w", newline="") as f:
        f.write(text.replace("\n", "\r\n") if crlf else text)
    print(f"\nWrote {path} (original saved as {path}.bak)."
          + (f" {len(skipped)} patch(es) need manual attention." if skipped else " All patches applied."))


if __name__ == "__main__":
    main()
