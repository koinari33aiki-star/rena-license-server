# -*- coding: utf-8 -*-
"""
RENA License Server (サーバー.py)
- 1ライセンスキー = 1PC (HWID バインド)
- HWID リセット可能
- 有効期限を設定可能（期限切れは自動で即時停止）
- ライセンスを停止 / 再開可能
- ライセンスを完全削除可能

期限切れ自動停止は3段構え:
  1) before_request  : リクエスト毎に間引きスイープ（スリープ復帰対策）
     ※ ヘルスチェック "/" は DB に触らない
  2) 常駐スレッド    : 一定間隔でスイープ（多重起動はファイルロックで防止）
  3) /admin/expire_sweep : 外部cronから叩ける

日付判定はすべて JST（日本時間 UTC+9）基準。
新規発行キー: duration_days=利用日数、activated_at=NULL、expiry_date=NULL。
初回の /api/activate 成功時に開始日と有効期限を確定。
従来の /admin/generate expiry=YYYY-MM-DD は発行日からの利用日数に変換。
既存DBの旧キー(duration_days=NULL)は従来の固定期限方式のまま維持。

[修正内容]
- DB 接続に connect_timeout を設定（ハング防止）
- 全 DB 操作を contextmanager で close 保証（接続枯渇防止）
- 起動時の init / sweep 失敗でプロセスが落ちないように
- ヘルスチェックでは sweep をスキップ
- スイーパースレッドの多重起動をファイルロックで防止
"""
import os
import time
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, date, timezone, timedelta
from flask import Flask, request, jsonify

try:
    import fcntl
except ImportError:  # Windows ローカル開発時
    fcntl = None

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me_please")
USE_PG = DATABASE_URL.startswith("postgres")
SWEEP_INTERVAL = int(os.environ.get("EXPIRE_SWEEP_INTERVAL", 60))  # 秒
DB_CONNECT_TIMEOUT = int(os.environ.get("DB_CONNECT_TIMEOUT", 5))  # 秒
SWEEPER_LOCK_FILE = os.environ.get("SWEEPER_LOCK_FILE", "/tmp/rena_sweeper.lock")

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
        return psycopg2.connect(DATABASE_URL, connect_timeout=DB_CONNECT_TIMEOUT)
    return sqlite3.connect(
        os.environ.get("DB_PATH", "rena.db"), timeout=DB_CONNECT_TIMEOUT
    )


@contextmanager
def _db():
    """DB 接続を必ず close するコンテキストマネージャ。commit は呼び出し側で行う。"""
    c = _conn()
    try:
        yield c
    finally:
        c.close()


def _ph(sql):
    return sql.replace("?", "%s") if USE_PG else sql


def _init_db():
    with _db() as c:
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
                last_seen_ts DOUBLE PRECISION DEFAULT 0,
                duration_days INTEGER,
                activated_at TEXT
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
        # 既存DBを壊さず新しいカラムだけ追加する。
        if USE_PG:
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS duration_days INTEGER")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS activated_at TEXT")
        else:
            cur.execute("PRAGMA table_info(licenses)")
            existing = {row[1] for row in cur.fetchall()}
            if "duration_days" not in existing:
                cur.execute("ALTER TABLE licenses ADD COLUMN duration_days INTEGER")
            if "activated_at" not in existing:
                cur.execute("ALTER TABLE licenses ADD COLUMN activated_at TEXT")
        c.commit()


def _duration_from_expiry(expiry):
    """従来クライアントの期限日を『今から何日分』に変換する。Noneは無期限。"""
    if expiry is None or expiry == "":
        return None
    try:
        requested = date.fromisoformat(str(expiry))
    except (ValueError, TypeError):
        raise ValueError("期限は YYYY-MM-DD 形式で指定してください")
    days = (requested - _today_jst()).days
    if days < 0:
        raise ValueError("過去の日付ではキーを発行できません")
    return days


def _duration_from_request(data):
    """新形式 duration_days があれば優先。旧形式 expiry も利用可能。"""
    if "duration_days" in data:
        raw = data["duration_days"]
        if raw is None or raw == "":
            return None
        if isinstance(raw, bool):
            raise ValueError("利用日数が不正です")
        try:
            days = int(raw)
        except (ValueError, TypeError):
            raise ValueError("利用日数は整数で指定してください")
        if str(raw).strip() != str(days) or days < 0 or days > 36500:
            raise ValueError("利用日数は0〜36500の整数で指定してください")
        return days
    return _duration_from_expiry(data.get("expiry"))


def _is_pending(duration_days, activated_at):
    return duration_days is not None and not activated_at


def _expiry_for_start(duration_days):
    """初回利用日を基点に確定。有効期限日は従来通り当日いっぱい有効。"""
    return (_today_jst() + timedelta(days=duration_days)).isoformat()


try:
    _init_db()
except Exception as e:
    # ここで落とすとヘルスチェック前にプロセスが死ぬ。起動は継続。
    print(f"[init_db] ERROR: {e}")


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
        with _db() as c:
            cur = c.cursor()
            cur.execute(_ph(
                "UPDATE licenses SET active=0 "
                "WHERE active=1 AND expiry_date IS NOT NULL AND expiry_date < ? "
                "AND NOT (duration_days IS NOT NULL AND activated_at IS NULL)"
            ), (today_str,))
            affected = cur.rowcount if cur.rowcount is not None else 0

            # 期限切れキーのセッションも無効化
            cur.execute(_ph(
                "DELETE FROM sessions WHERE license_key IN ("
                "  SELECT license_key FROM licenses "
                "  WHERE active=0 AND expiry_date IS NOT NULL AND expiry_date < ? "
                "  AND NOT (duration_days IS NOT NULL AND activated_at IS NULL)"
                ")"
            ), (today_str,))
            c.commit()
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
        global _last_sweep_ts

        # gunicorn の worker が複数でもスイーパーは1プロセスだけ動かす
        lock_handle = None
        if fcntl is not None:
            try:
                lock_handle = open(SWEEPER_LOCK_FILE, "w")
                fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                print("[expire_sweep] another worker holds lock; sweeper skipped")
                if lock_handle:
                    lock_handle.close()
                return

        while True:
            try:
                _expire_sweep()
                _last_sweep_ts = time.time()
            except Exception as e:
                print(f"[expire_sweep thread] {e}")
            time.sleep(SWEEP_INTERVAL)

    t = threading.Thread(target=loop, daemon=True, name="expire-sweeper")
    t.start()
    print(f"[expire_sweep] thread started (interval={SWEEP_INTERVAL}s)")


# 起動時に既存の期限切れを一掃 → 常駐スレッド起動
try:
    _expire_sweep()
except Exception as e:
    print(f"[startup sweep] ERROR: {e}")
_last_sweep_ts = time.time()
_start_expire_sweeper()


# ---- リクエスト毎の保険スイープ ----
@app.before_request
def _sweep_on_request():
    # ヘルスチェックは DB に触らない（DB不調でインスタンスが落ちるのを防ぐ）
    if request.path == "/":
        return
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

    with _db() as c:
        cur = c.cursor()
        # 2台が同時に初回認証しても開始日/HWIDは一度だけ確定する。
        # PostgreSQLは行ロック、SQLiteは書込トランザクションで直列化。
        if not USE_PG:
            cur.execute("BEGIN IMMEDIATE")
        cur.execute(_ph(
            "SELECT hwid, expiry_date, max_launches, launch_count, active, "
            "duration_days, activated_at FROM licenses WHERE license_key=?" +
            (" FOR UPDATE" if USE_PG else "")
        ), (key,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "reason": "ライセンスキーが存在しません"}), 404

        stored_hwid, expiry_date, max_launches, launch_count, active, duration_days, activated_at = row
        if not active:
            return jsonify({"ok": False, "reason": "このライセンスは停止中です"}), 403
        if stored_hwid and stored_hwid != hwid:
            return jsonify({"ok": False, "reason": "このキーは別のPCに紐付いています。管理者にHWリセットを依頼してください。"}), 403

        next_count = (launch_count or 0) + 1
        if max_launches and max_launches > 0 and next_count > max_launches:
            return jsonify({"ok": False, "reason": "起動回数の上限に達しました"}), 403

        first_use = _is_pending(duration_days, activated_at)
        if first_use:
            expiry_date = _expiry_for_start(duration_days)
            activated_at = datetime.now(JST).isoformat()
        elif expiry_date:
            try:
                exp = date.fromisoformat(expiry_date)
            except ValueError:
                return jsonify({"ok": False, "reason": "保存された有効期限が不正です"}), 500
            if _today_jst() > exp:
                if active:
                    cur.execute(_ph("UPDATE licenses SET active=0 WHERE license_key=?"), (key,))
                    c.commit()
                return jsonify({"ok": False, "reason": f"有効期限切れ ({expiry_date})"}), 403

        now = time.time()
        cur.execute(_ph(
            "UPDATE licenses SET hwid=?, expiry_date=?, activated_at=?, "
            "launch_count=?, last_seen_ts=? WHERE license_key=?"
        ), (hwid, expiry_date, activated_at, next_count, now, key))
        cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
        token = secrets.token_urlsafe(48)
        cur.execute(_ph(
            "INSERT INTO sessions (token, license_key, hwid, created_at, last_heartbeat) "
            "VALUES (?,?,?,?,?)"
        ), (token, key, hwid, now, now))
        c.commit()
        return jsonify({
            "ok": True, "token": token, "expiry": expiry_date,
            "launch_count": next_count, "max_launches": max_launches,
            "activated_at": activated_at, "duration_days": duration_days,
            "first_use": first_use
        })


@app.route("/api/validate_start", methods=["POST"])
def validate_start():
    """起動時専用HWID検証。起動後のheartbeatではHWIDを確認しない。"""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    if not token or not hwid:
        return jsonify({"ok": False, "reason": "トークンまたはHWIDがありません"}), 400

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("SELECT license_key, hwid FROM sessions WHERE token=?"), (token,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "reason": "セッションが無効です"}), 401
        license_key, session_hwid = row
        cur.execute(_ph(
            "SELECT hwid, expiry_date, max_launches, launch_count, active "
            "FROM licenses WHERE license_key=?"), (license_key,))
        lic = cur.fetchone()
        if not lic:
            return jsonify({"ok": False, "reason": "ライセンスが見つかりません"}), 404
        license_hwid, expiry_date, max_launches, launch_count, active = lic
        if session_hwid != hwid or license_hwid != hwid:
            return jsonify({"ok": False, "reason": "HWIDが一致しません。別のPCでは起動できません。"}), 403
        if expiry_date:
            try:
                exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            except ValueError:
                exp = None
            if exp is not None and _today_jst() > exp:
                if active:
                    cur.execute(_ph("UPDATE licenses SET active=0 WHERE license_key=?"), (license_key,))
                    c.commit()
                return jsonify({"ok": False, "reason": f"有効期限切れ ({expiry_date})"}), 403
        if not active:
            return jsonify({"ok": False, "reason": "ライセンスが停止中です"}), 403
        now = time.time()
        cur.execute(_ph("UPDATE sessions SET last_heartbeat=? WHERE token=?"), (now, token))
        cur.execute(_ph("UPDATE licenses SET last_seen_ts=? WHERE license_key=?"), (now, license_key))
        c.commit()
        return jsonify({"ok": True, "expiry": expiry_date,
                        "launch_count": launch_count, "max_launches": max_launches})


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    """起動後の継続確認。HWIDではなくサーバー発行tokenを検証する。"""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "reason": "トークンがありません"}), 400

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("SELECT license_key FROM sessions WHERE token=?"), (token,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "reason": "セッションが無効です"}), 401
        license_key = row[0]
        cur.execute(_ph(
            "SELECT expiry_date, max_launches, launch_count, active "
            "FROM licenses WHERE license_key=?"), (license_key,))
        lic = cur.fetchone()
        if not lic:
            return jsonify({"ok": False, "reason": "ライセンスが見つかりません"}), 404
        expiry_date, max_launches, launch_count, active = lic
        if expiry_date:
            try:
                exp = datetime.strptime(expiry_date, "%Y-%m-%d").date()
            except ValueError:
                exp = None
            if exp is not None and _today_jst() > exp:
                if active:
                    cur.execute(_ph("UPDATE licenses SET active=0 WHERE license_key=?"), (license_key,))
                    c.commit()
                return jsonify({"ok": False, "reason": f"有効期限切れ ({expiry_date})"}), 403
        if not active:
            return jsonify({"ok": False, "reason": "ライセンスが停止中です"}), 403
        now = time.time()
        cur.execute(_ph("UPDATE sessions SET last_heartbeat=? WHERE token=?"), (now, token))
        cur.execute(_ph("UPDATE licenses SET last_seen_ts=? WHERE license_key=?"), (now, license_key))
        c.commit()
        return jsonify({"ok": True, "expiry": expiry_date,
                        "launch_count": launch_count, "max_launches": max_launches})


# ===================================================================
# 管理者API (全て admin_secret 必須)
# ===================================================================

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    """キー作り置き: duration_days または旧形式 expiry（発行日からの日数）を指定。"""
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    try:
        days = _duration_from_request(data)
        max_launches = int(data.get("max_launches", 0))
        count = int(data.get("count", 1))
        if not 1 <= count <= 1000 or max_launches < 0:
            raise ValueError("発行数は1〜1000、起動上限は0以上で指定してください")
    except (TypeError, ValueError) as e:
        return jsonify({"ok": False, "reason": str(e)}), 400

    keys = []
    with _db() as c:
        cur = c.cursor()
        for _ in range(count):
            k = secrets.token_hex(16).upper()
            # 未使用キーには期限日を入れない。初回の認証成功で確定する。
            cur.execute(_ph(
                "INSERT INTO licenses (license_key, hwid, expiry_date, "
                "max_launches, launch_count, active, created_at, last_seen_ts, "
                "duration_days, activated_at) VALUES (?,?,?,?,?,?,?,?,?,?)"
            ), (k, None, None, max_launches, 0, 1,
                datetime.now(JST).isoformat(), 0, days, None))
            keys.append(k)
        c.commit()
    return jsonify({"ok": True, "keys": keys, "duration_days": days,
                    "starts_on_first_use": days is not None})


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

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("UPDATE licenses SET hwid=NULL WHERE license_key=?"), (key,))
        cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
        c.commit()

    return jsonify({"ok": True, "reason": "HWIDをリセットしました"})


@app.route("/admin/set_expiry", methods=["POST"])
def admin_set_expiry():
    """未使用キーは日数を変更、使用済みキーは従来通り期限日を変更。"""
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401
    key = (data.get("license_key") or "").strip()
    if not key:
        return jsonify({"ok": False, "reason": "キーが空です"}), 400
    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("SELECT duration_days, activated_at FROM licenses WHERE license_key=?"), (key,))
        row = cur.fetchone()
        if not row:
            return jsonify({"ok": False, "reason": "キーが存在しません"}), 404
        pending = _is_pending(*row)
        if pending:
            try:
                days = _duration_from_request(data)
            except ValueError as e:
                return jsonify({"ok": False, "reason": str(e)}), 400
            # None = 永久。永久へ変更しても使用開始日を記録しない設計。
            cur.execute(_ph("UPDATE licenses SET duration_days=?, expiry_date=NULL WHERE license_key=?"), (days, key))
            reason = f"未使用キーの利用期間を {days}日 に変更しました" if days is not None else "未使用キーを無期限に変更しました"
        else:
            expiry = data.get("expiry")
            if expiry is not None and expiry != "":
                try:
                    date.fromisoformat(str(expiry))
                except ValueError:
                    return jsonify({"ok": False, "reason": "期限はYYYY-MM-DD形式です"}), 400
            else:
                expiry = None
            cur.execute(_ph("UPDATE licenses SET expiry_date=? WHERE license_key=?"), (expiry, key))
            reason = f"期限を {expiry or '無期限'} に設定しました"
        c.commit()
    return jsonify({"ok": True, "reason": reason})


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

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("UPDATE licenses SET active=? WHERE license_key=?"),
                    (active, key))
        if not active:
            cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
        c.commit()

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

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph("SELECT 1 FROM licenses WHERE license_key=?"), (key,))
        if not cur.fetchone():
            return jsonify({"ok": False, "reason": "キーが存在しません"}), 404

        cur.execute(_ph("DELETE FROM sessions WHERE license_key=?"), (key,))
        cur.execute(_ph("DELETE FROM licenses WHERE license_key=?"), (key,))
        c.commit()

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

    with _db() as c:
        cur = c.cursor()
        cur.execute(_ph(
            "SELECT license_key, hwid, expiry_date, max_launches, launch_count, "
            "active, created_at, last_seen_ts, duration_days, activated_at FROM licenses WHERE license_key=?"
        ), (key,))
        row = cur.fetchone()

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
        "duration_days": row[8],
        "activated_at": row[9],
        "pending": _is_pending(row[8], row[9]),
    })


@app.route("/admin/list", methods=["POST"])
def admin_list():
    """全キー一覧
    { "admin_secret":"..." }
    """
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"ok": False, "reason": "Unauthorized"}), 401

    today_str = _today_jst().isoformat()
    with _db() as c:
        cur = c.cursor()

        # 一覧取得時にも念のため期限切れを一括停止（JST基準）
        cur.execute(_ph(
            "UPDATE licenses SET active = 0 WHERE active = 1 "
            "AND expiry_date IS NOT NULL AND expiry_date < ? "
            "AND NOT (duration_days IS NOT NULL AND activated_at IS NULL)"
        ), (today_str,))
        c.commit()

        cur.execute(_ph(
            "SELECT license_key, hwid, expiry_date, max_launches, launch_count, "
            "active, created_at, duration_days, activated_at "
            "FROM licenses ORDER BY created_at DESC"
        ))
        rows = cur.fetchall()

    keys = [{
        "license_key": r[0],
        "hwid": r[1],
        "expiry": r[2],
        "max_launches": r[3],
        "launch_count": r[4],
        "active": bool(r[5]),
        "created_at": r[6],
        "duration_days": r[7],
        "activated_at": r[8],
        "pending": _is_pending(r[7], r[8]),
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
        with _db() as c:
            cur = c.cursor()
            cur.execute(_ph(
                "SELECT COUNT(*) FROM licenses "
                "WHERE active=1 AND expiry_date IS NOT NULL AND expiry_date < ? "
                "AND NOT (duration_days IS NOT NULL AND activated_at IS NULL)"
            ), (today_str,))
            pending = cur.fetchone()[0]
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
