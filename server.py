# -*- coding: utf-8 -*-
"""
RENA License Server
- 1ライセンスキー = 1PC (HWID バインド)
- HWID リセット可能
- 有効期限を設定可能
- ライセンスを停止 / 再開可能
- ライセンスを完全削除可能
"""
import os
import time
import secrets
import sqlite3
from datetime import datetime, date
from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me_please")
USE_PG = DATABASE_URL.startswith("postgres")

if USE_PG:
    import psycopg2


def _conn():
    if USE_PG:
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(os.environ.get("DB_PATH", "rena.db"))


def _ph(sql):
    return sql.replace("?", "%s") if USE_PG else sql


def _init_db():
    c = _conn()
    cur = c.cursor()
    cur.execute(_ph("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            hwid TEXT,
            expiry_date TEXT,
            max_launches INTEGER DEFAULT 0,
            launch_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT,
            last_seen_ts DOUBLE PRECISION DEFAULT 0
        )
    """))
    cur.execute(_ph("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            license_key TEXT,
            hwid TEXT,
            created_at DOUBLE PRECISION,
            last_heartbeat DOUBLE PRECISION
        )
    """))
    c.commit()
    c.close()


_init_db()


def _check_admin(data):
    return data.get("admin_secret") == ADMIN_SECRET


# ===================================================================
# ヘルスチェック
# ===================================================================
@app.route("/")
def health():
    return jsonify({"status": "ok", "service": "RENA License Server"})


# ===================================================================
# 一般API
# ===================================================================
@app.route("/api/activate", methods=["POST"])
def activate():
    data = request.get_json(silent=True) or {}
    key = (data.get("license_key") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not key or not hwid:
        return jsonify({"ok": False, "reason": "キーまたはHWIDが空です"}), 400

    c = _conn()
    cur = c.cursor()
    cur.execute(_ph(
        "SELECT hwid, expiry_date, max_launches, launch_count, active "
        "FROM licenses WHERE license_key=?"
    ), (key,))
    row = cur.fetchone()

    if not row:
        c.close()
        return jsonify({"ok": False, "reason": "ライセンスキーが存在しません"}), 404

    stored_hwid, expiry_date, max_launches, launch_count, active = row

    if not active:
        c.close()
        return jsonify({"ok": False, "reason": "このライセンスは停止中です"}), 403

    # HWID バインド (初回)
    if not stored_hwid:
        cur.execute(_ph("UPDATE licenses SET hwid=? WHERE license_key=?"),
                    (hwid, key))
    elif stored_hwid != hwid:
        c.close()
        return jsonify({
            "ok": False,
            "reason": "このキーは別のPCに紐付いています。管理者にHWリセットを依頼してください。"
        }), 403

    # 期限チェック
    if expiry_date:
        try:
            exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            if date.today() > exp:
                c.close()
                return jsonify({"ok": False,
                                "reason": f"有効期限切れ ({expiry_date})"}), 403
        except ValueError:
            pass

    # 起動回数
    launch_count = (launch_count or 0) + 1
    if max_launches and max_launches > 0 and launch_count > max_launches:
        c.close()
        return jsonify({"ok": False,
                        "reason": "起動回数の上限に達しました"}), 403

    cur.execute(_ph(
        "UPDATE licenses SET launch_count=?, last_seen_ts=? WHERE license_key=?"
    ), (launch_count, time.time(), key))

    # 同キーの旧セッションは破棄 (1PC = 1セッション)
    cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))

    token = secrets.token_urlsafe(48)
    now = time.time()
    cur.execute(_ph(
        "INSERT INTO sessions (token, license_key, hwid, created_at, last_heartbeat) "
        "VALUES (?,?,?,?,?)"
    ), (token, key, hwid, now, now))
    c.commit()
    c.close()

    return jsonify({
        "ok": True,
        "token": token,
        "expiry": expiry_date,
        "launch_count": launch_count,
        "max_launches": max_launches
    })


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    hwid = (data.get("hwid") or "").strip()

    if not token or not hwid:
        return jsonify({"ok": False, "reason": "トークンまたはHWIDがありません"}), 400

    c = _conn()
    cur = c.cursor()
    cur.execute(_ph("SELECT license_key, hwid FROM sessions WHERE token=?"),
                (token,))
    row = cur.fetchone()
    if not row:
        c.close()
        return jsonify({"ok": False, "reason": "セッションが無効です"}), 401

    license_key, stored_hwid = row
    if stored_hwid != hwid:
        c.close()
        return jsonify({"ok": False, "reason": "HWIDが一致しません"}), 401

    cur.execute(_ph(
        "SELECT expiry_date, max_launches, launch_count, active "
        "FROM licenses WHERE license_key=?"
    ), (license_key,))
    lic = cur.fetchone()
    if not lic:
        c.close()
        return jsonify({"ok": False, "reason": "ライセンスが見つかりません"}), 404

    expiry_date, max_launches, launch_count, active = lic

    if not active:
        c.close()
        return jsonify({"ok": False, "reason": "ライセンスが停止中です"}), 403

    if expiry_date:
        try:
            exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            if date.today() > exp:
                c.close()
                return jsonify({"ok": False,
                                "reason": f"有効期限切れ ({expiry_date})"}), 403
        except ValueError:
            pass

    now = time.time()
    cur.execute(_ph("UPDATE sessions SET last_heartbeat=? WHERE token=?"),
                (now, token))
    cur.execute(_ph("UPDATE licenses SET last_seen_ts=? WHERE license_key=?"),
                (now, license_key))
    c.commit()
    c.close()

    return jsonify({
        "ok": True,
        "expiry": expiry_date,
        "launch_count": launch_count,
        "max_launches": max_launches
    })


# ===================================================================
# 管理者API (全て admin_secret 必須)
# ===================================================================

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    """キー発行
    { "admin_secret":"...", "expiry":"2026-12-31" or null,
      "max_launches":0, "count":1 }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401

    expiry = data.get("expiry")           # "YYYY-MM-DD" or None
    max_launches = int(data.get("max_launches", 0))
    count = max(1, int(data.get("count", 1)))

    keys = []
    c = _conn()
    cur = c.cursor()
    for _ in range(count):
        # ★ プレフィックス無しのライセンスキー
        k = secrets.token_hex(16).upper()
        cur.execute(_ph(
            "INSERT INTO licenses (license_key, hwid, expiry_date, "
            "max_launches, launch_count, active, created_at, last_seen_ts) "
            "VALUES (?,?,?,?,?,?,?,?)"
        ), (k, None, expiry, max_launches, 0, 1,
            datetime.utcnow().isoformat(), 0))
        keys.append(k)
    c.commit()
    c.close()
    return jsonify({"ok": True, "keys": keys})


@app.route("/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    """HWリセット: キーの HWID バインドを解除して別PCで使えるようにする
    { "admin_secret":"...", "license_key":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    if not key:
        return jsonify({"ok": False, "reason": "キーが空です"}), 400

    c = _conn()
    cur = c.cursor()
    cur.execute(_ph("UPDATE licenses SET hwid=NULL WHERE license_key=?"), (key,))
    cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
    c.commit()
    c.close()
    return jsonify({"ok": True, "reason": "HWIDをリセットしました"})


@app.route("/admin/set_expiry", methods=["POST"])
def admin_set_expiry():
    """有効期限を設定 / 変更 / 無期限化
    { "admin_secret":"...", "license_key":"...", "expiry":"2026-12-31" or null }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    if not key:
        return jsonify({"ok": False, "reason": "キーが空です"}), 400
    expiry = data.get("expiry")  # None で無期限

    c = _conn()
    cur = c.cursor()
    cur.execute(_ph("UPDATE licenses SET expiry_date=? WHERE license_key=?"),
                (expiry, key))
    c.commit()
    c.close()
    return jsonify({"ok": True,
                    "reason": f"期限を {expiry or '無期限'} に設定しました"})


@app.route("/admin/toggle", methods=["POST"])
def admin_toggle():
    """ライセンスの停止 / 開始
    { "admin_secret":"...", "license_key":"...", "active": true/false }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    active = int(bool(data.get("active", True)))
    if not key:
        return jsonify({"ok": False, "reason": "キーが空です"}), 400

    c = _conn()
    cur = c.cursor()
    cur.execute(_ph("UPDATE licenses SET active=? WHERE license_key=?"),
                (active, key))
    if not active:
        cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
    c.commit()
    c.close()
    return jsonify({"ok": True,
                    "reason": "有効化しました" if active else "停止しました"})


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    """ライセンスを完全削除
    { "admin_secret":"...", "license_key":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    if not key:
        return jsonify({"ok": False, "reason": "キーが空です"}), 400

    c = _conn()
    cur = c.cursor()
    # 存在チェック
    cur.execute(_ph("SELECT 1 FROM licenses WHERE license_key=?"), (key,))
    if not cur.fetchone():
        c.close()
        return jsonify({"ok": False, "reason": "キーが存在しません"}), 404

    cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
    cur.execute(_ph("DELETE FROM licenses WHERE license_key=?"), (key,))
    c.commit()
    c.close()
    return jsonify({"ok": True, "reason": "ライセンスを削除しました"})


@app.route("/admin/info", methods=["POST"])
def admin_info():
    """キーの状態を取得
    { "admin_secret":"...", "license_key":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    c = _conn()
    cur = c.cursor()
    cur.execute(_ph(
        "SELECT license_key, hwid, expiry_date, max_launches, launch_count, "
        "active, created_at, last_seen_ts FROM licenses WHERE license_key=?"
    ), (key,))
    row = cur.fetchone()
    c.close()
    if not row:
        return jsonify({"ok": False, "reason": "キーが存在しません"}), 404
    return jsonify({
        "ok": True,
        "license_key": row[0],
        "hwid": row[1],
        "expiry": row[2],
        "max_launches": row[3],
        "launch_count": row[4],
        "active": bool(row[5]),
        "created_at": row[6],
        "last_seen_ts": row[7],
    })


@app.route("/admin/list", methods=["POST"])
def admin_list():
    """全キー一覧
    { "admin_secret":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    c = _conn()
    cur = c.cursor()
    cur.execute(_ph(
        "SELECT license_key, hwid, expiry_date, max_launches, launch_count, "
        "active, created_at FROM licenses ORDER BY created_at DESC"
    ))
    rows = cur.fetchall()
    c.close()
    keys = [{
        "license_key": r[0],
        "hwid": r[1],
        "expiry": r[2],
        "max_launches": r[3],
        "launch_count": r[4],
        "active": bool(r[5]),
        "created_at": r[6],
    } for r in rows]
    return jsonify({"ok": True, "licenses": keys})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
