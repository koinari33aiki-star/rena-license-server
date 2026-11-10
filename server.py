

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
            "active, created_at, last_seen_ts FROM licenses WHERE license_key=?"
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
            "AND expiry_date IS NOT NULL AND expiry_date < ?"
        ), (today_str,))
        c.commit()

        cur.execute(_ph(
            "SELECT license_key, hwid, expiry_date, max_launches, launch_count, "
            "active, created_at FROM licenses ORDER BY created_at DESC"
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
                "WHERE active=1 AND expiry_date IS NOT NULL AND expiry_date < ?"
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
