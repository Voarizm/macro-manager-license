"""
Voar's Macro Manager - license & trial server.

Replaces the client-side HMAC secret (_k9f2 in the .ahk script) with a
server-held one. The client never sees SECRET_KEY, so it can't forge
trial checksums or activation keys - the thing that was ultimately
unfixable on the client side alone.

Run locally for testing:
    pip install -r requirements.txt
    export LICENSE_SECRET_KEY="put a long random string here"
    export LICENSE_ADMIN_TOKEN="a different long random string"
    python server.py

For production: put this behind HTTPS (a $5-6/mo VPS with Caddy/nginx
doing TLS termination, or a platform like Render/Fly.io/PythonAnywhere
that gives you HTTPS for free, all work fine for this load). Never
serve it over plain HTTP - the whole point is a secret that shouldn't
be interceptable either.

Endpoints
---------
POST /trial
    body:  {"hwid": "<hardware id string from the client>"}
    reply: {"state": "new"|"active"|"expired", "hoursLeft": <float>}
    First call for a given hwid starts the clock server-side; every
    later call just reports elapsed/remaining time. Nothing about
    trial state is ever stored on the client - there is nothing local
    to delete to "reset" it.

POST /activate
    body:  {"installId": "...", "key": "..."}
    reply: {"valid": true|false}
    Checks a key the same way the old _iva8h()/_gak7g() did, just with
    the secret living only here.

POST /issue   (admin only - you run this yourself after a payment
               comes in, e.g. via curl or a tiny admin page; it's not
               meant to be called by the app)
    body:  {"installId": "...", "adminToken": "..."}
    reply: {"key": "..."}
    Generates the activation key for a given Installation ID. This is
    the direct replacement for the app computing its own key locally.
"""

import hashlib
import hmac
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify

SECRET_KEY = os.environ.get("LICENSE_SECRET_KEY", "")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "")
TRIAL_HOURS = float(os.environ.get("LICENSE_TRIAL_HOURS", "48"))
DB_PATH = os.environ.get("LICENSE_DB_PATH", "license.db")

if not SECRET_KEY or not ADMIN_TOKEN:
    raise SystemExit(
        "Set LICENSE_SECRET_KEY and LICENSE_ADMIN_TOKEN env vars before "
        "starting the server (long, random, kept out of source control)."
    )

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS trials ("
        " hwid TEXT PRIMARY KEY,"
        " start_epoch REAL NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS activations ("
        " install_id TEXT PRIMARY KEY,"
        " issued_epoch REAL NOT NULL"
        ")"
    )
    return conn


def normalize(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip()).upper()


def group5(hexstr: str, take: int = 20) -> str:
    s = hexstr[:take].upper()
    return "-".join(s[i:i + 5] for i in range(0, len(s), 5))


def make_key(install_id: str) -> str:
    norm = normalize(install_id)
    mac = hmac.new(SECRET_KEY.encode(), norm.encode(), hashlib.sha256).hexdigest().upper()
    return group5(mac)


@app.post("/trial")
def trial():
    body = request.get_json(silent=True) or {}
    hwid = normalize(body.get("hwid", ""))
    if not hwid:
        return jsonify(error="missing hwid"), 400

    now = time.time()
    conn = db()
    try:
        row = conn.execute(
            "SELECT start_epoch FROM trials WHERE hwid = ?", (hwid,)
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO trials (hwid, start_epoch) VALUES (?, ?)",
                (hwid, now),
            )
            conn.commit()
            return jsonify(state="new", hoursLeft=TRIAL_HOURS)

        start_epoch = row[0]
        elapsed_hours = (now - start_epoch) / 3600.0
        if elapsed_hours >= TRIAL_HOURS:
            return jsonify(state="expired", hoursLeft=0)
        return jsonify(state="active", hoursLeft=round(TRIAL_HOURS - elapsed_hours, 2))
    finally:
        conn.close()


@app.post("/activate")
def activate():
    body = request.get_json(silent=True) or {}
    install_id = body.get("installId", "")
    key = normalize(body.get("key", ""))
    if not install_id or not key:
        return jsonify(error="missing installId or key"), 400

    valid = hmac.compare_digest(key, make_key(install_id))
    return jsonify(valid=valid)


@app.post("/issue")
def issue():
    body = request.get_json(silent=True) or {}
    if not hmac.compare_digest(body.get("adminToken", ""), ADMIN_TOKEN):
        return jsonify(error="unauthorized"), 401

    install_id = body.get("installId", "")
    if not install_id:
        return jsonify(error="missing installId"), 400

    key = make_key(install_id)
    conn = db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO activations (install_id, issued_epoch) VALUES (?, ?)",
            (normalize(install_id), time.time()),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify(key=key)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8787")))
