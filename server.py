# -*- coding: utf-8 -*-
"""
RENA License Server
- 1ライセンスキー = 1PC (HWID バインド)
- HWID リセット可能
- 有効期限を設定可能（期限切れは自動で即時停止）
- ライセンスを停止 / 再開可能
- ライセンスを完全削除可能

期限切れ自動停止は3段構え:
  1) before_request  : リクエスト毎に間引きスイープ（スリープ復帰対策）
  2) 常駐スレッド    : 一定間隔でスイープ
  3) /admin/expire_sweep : 外部cronから叩ける

日付判定はすべて JST（日本時間 UTC+9）基準。
"""
import os
import time
import secrets
import sqlite3
import threading
from datetime import datetime, date, timezone, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me_please")
USE_PG = DATABASE_URL.startswith("postgres")
SWEEP_INTERVAL = int(os.environ.get("EXPIRE_SWEEP_INTERVAL", 60))  # 秒

if USE_PG:
    import psycopg2


# ===================================================================
# 日本時間 (UTC+9)
# ===================================================================
JST = timezone(timedelta(hours=9))


def _today_jst():
    """日本時間の今日の日付を返す"""
    return datetime.now(JST).date()


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
# 期限切れ自動スイープ
# ===================================================================
_sweep_count = 0
_last_sweep_ts = 0.0
_sweep_lock = threading.Lock()


def _expire_sweep():
    """期限切れのライセンスを一括で active=0 にする（冪等）"""
    global _sweep_count
    today_str = _today_jst().isoformat()
    affected = 0
    try:
        c = _conn()
        cur = c.cursor()
        cur.execute(_ph(
            "UPDATE licenses SET active=0 "
            "WHERE active=1 AND expiry_date IS NOT NULL AND expiry_date < ?"
        ), (today_str,))
        affected = cur.rowcount if cur.rowcount is not None else 0

        # 期限切れキーのセッションも無効化
        cur.execute(_ph(
            "DELETE FROM sessions WHERE license_key IN ("
            "  SELECT license_key FROM licenses "
            "  WHERE active=0 AND expiry_date IS NOT NULL AND expiry_date < ?"
            ")"
        ), (today_str,))
        c.commit()
        c.close()
    except Exception as e:
        print(f"[expire_sweep] ERROR: {e}")
        return 0

    _sweep_count += 1
    if affected or _sweep_count % 10 == 1:
        print(f"[expire_sweep] #{_sweep_count} today={today_str} stopped={affected}")
    return affected


def _maybe_sweep():
    """前回から SWEEP_INTERVAL 秒以上経過していればスイープ。
    リクエスト毎に呼ばれるので、スリープ復帰直後でも必ず走る。"""
    global _last_sweep_ts
    now = time.time()
    with _sweep_lock:
        if now - _last_sweep_ts < SWEEP_INTERVAL:
            return 0
        _last_sweep_ts = now
    return _expire_sweep()


# ---- 常駐スレッド ----
_sweeper_started = False
_sweeper_start_lock = threading.Lock()


def _start_expire_sweeper():
    global _sweeper_started
    with _sweeper_start_lock:
        if _sweeper_started:
            return
        _sweeper_started = True

    def loop():
        while True:
            try:
                _expire_sweep()
                global _last_sweep_ts
                _last_sweep_ts = time.time()
            except Exception as e:
                print(f"[expire_sweep thread] {e}")
            time.sleep(SWEEP_INTERVAL)

    t = threading.Thread(target=loop, daemon=True, name="expire-sweeper")
    t.start()
    print(f"[expire_sweep] thread started (interval={SWEEP_INTERVAL}s)")


# 起動時に既存の期限切れを一掃 → 常駐スレッド起動
_expire_sweep()
_last_sweep_ts = time.time()
_start_expire_sweeper()


# ---- リクエスト毎の保険スイープ ----
@app.before_request
def _sweep_on_request():
    try:
        _maybe_sweep()
    except Exception as e:
        print(f"[before_request sweep] {e}")


# ===================================================================
# ヘルスチェック
# ===================================================================
@app.route("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "RENA License Server",
        "today": _today_jst().isoformat(),
        "sweep_count": _sweep_count,
        "last_sweep_ago": round(time.time() - _last_sweep_ts, 1),
    })


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

    # 期限チェック (期限切れの場合は自動で active = 0 に更新)
    if expiry_date:
        try:
            exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            if _today_jst() > exp:
                if active:
                    cur.execute(_ph("UPDATE licenses SET active=0 WHERE license_key=?"), (key,))
                    c.commit()
                c.close()
                return jsonify({"ok": False,
                                "reason": f"有効期限切れ ({expiry_date})"}), 403
        except ValueError:
            pass

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

    # 期限チェック
    if expiry_date:
        try:
            exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            if _today_jst() > exp:
                if active:
                    cur.execute(_ph("UPDATE licenses SET active=0 WHERE license_key=?"), (license_key,))
                    c.commit()
                c.close()
                return jsonify({"ok": False,
                                "reason": f"有効期限切れ ({expiry_date})"}), 403
        except ValueError:
            pass

    if not active:
        c.close()
        return jsonify({"ok": False, "reason": "ライセンスが停止中です"}), 403

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

    expiry = data.get("expiry")            # "YYYY-MM-DD" or None
    max_launches = int(data.get("max_launches", 0))
    count = max(1, int(data.get("count", 1)))

    keys = []
    c = _conn()
    cur = c.cursor()
    for _ in range(count):
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
    expiry = data.get("expiry")

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

    # 一覧取得時にも念のため期限切れを一括停止（JST基準）
    today_str = _today_jst().isoformat()
    cur.execute(_ph(
        "UPDATE licenses SET active = 0 WHERE active = 1 "
        "AND expiry_date IS NOT NULL AND expiry_date < ?"
    ), (today_str,))
    c.commit()

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


@app.route("/admin/expire_sweep", methods=["POST"])
def admin_expire_sweep():
    """期限切れキーを今すぐ一括停止（外部cron用）
    { "admin_secret":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    affected = _expire_sweep()
    return jsonify({"ok": True, "stopped": affected})


@app.route("/admin/sweeper_status", methods=["POST"])
def admin_sweeper_status():
    """スイープの生存確認・診断用
    { "admin_secret":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401

    today_str = _today_jst().isoformat()
    pending = -1
    try:
        c = _conn()
        cur = c.cursor()
        cur.execute(_ph(
            "SELECT COUNT(*) FROM licenses "
            "WHERE active=1 AND expiry_date IS NOT NULL AND expiry_date < ?"
        ), (today_str,))
        pending = cur.fetchone()[0]
        c.close()
    except Exception as e:
        print(f"[sweeper_status] {e}")

    return jsonify({
        "ok": True,
        "today": today_str,
        "sweep_interval_sec": SWEEP_INTERVAL,
        "sweep_count": _sweep_count,
        "last_sweep_ago_sec": round(time.time() - _last_sweep_ts, 1),
        "thread_started": _sweeper_started,
        # 0 なら正常。1以上なら「止めるべきキーが残っている」= スイープ未実行
        "pending_expired_active": pending,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
