import ipaddress

from db import get_connection
from verdict import combine


def run_query(sql, params=()):
    conn = get_connection()
    rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def report_volume_by_hour():
    return run_query(
        "SELECT hour, total, warnings FROM v_volume_by_hour ORDER BY hour"
    )


def report_events_by_level_and_type():
    return run_query(
        "SELECT level, event_type, n FROM v_events_by_level_type "
        "ORDER BY level DESC, n DESC, event_type"
    )


def report_top_source_ips():
    return run_query(
        "SELECT src_ip, total, failures FROM v_top_source_ips "
        "ORDER BY total DESC, src_ip LIMIT 5"
    )


def report_auth_failures_by_user():
    return run_query(
        "SELECT username, failures, ips, first_seen, last_seen "
        "FROM v_auth_failures_by_user ORDER BY failures DESC, username"
    )


def report_ai_findings():
    return run_query(
        "SELECT severity, title, mitre_id, mitre_name, tactic, host, src_ip, first_seen, status, meaning, action, model FROM v_findings "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC, id DESC LIMIT 10"
    )


def report_summary():
    return run_query(
        "SELECT events, warnings, auth_failures, hosts, findings FROM v_summary"
    )[0]


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def report_ip_reputation(limit=20):
    conn = get_connection()
    try:
        ip_rows = conn.execute(
            "SELECT src_ip, COUNT(*) AS events, "
            "SUM(event_type = 'auth_failure') AS failures "
            "FROM events WHERE src_ip IS NOT NULL "
            "GROUP BY src_ip ORDER BY events DESC, src_ip"
        ).fetchall()
        intel_rows = conn.execute(
            "SELECT ip, source, verdict, checked_at FROM ip_reputation"
        ).fetchall()
    finally:
        conn.close()

    by_ip = {}
    for row in intel_rows:
        by_ip.setdefault(row["ip"], []).append(row)

    out = []
    for r in ip_rows:
        ip = r["src_ip"]
        if not is_public(ip):
            continue
        rows = by_ip.get(ip, [])
        entry = {
            "ip": ip,
            "events": r["events"],
            "failures": r["failures"],
            "verdict": "not checked",
            "points": 0,
            "reasons": [],
            "per_source": {},
            "checked_at": None,
        }
        if rows:
            combined = combine(
                [{"source": x["source"], "verdict": x["verdict"]} for x in rows]
            )
            entry["verdict"] = combined["verdict"]
            entry["points"] = combined["points"]
            entry["reasons"] = combined["reasons"]
            entry["per_source"] = {x["source"]: x["verdict"] for x in rows}
            entry["checked_at"] = max(x["checked_at"] for x in rows)
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def show(title, rows, columns):
    print(f"\n{title}")
    if not rows:
        print("  (no data yet)")
        return
    print("  " + " | ".join(columns))
    for row in rows:
        print("  " + " | ".join(str(row[c]) for c in columns))


if __name__ == "__main__":
    show("Report 1: Log volume by hour", report_volume_by_hour(),
         ["hour", "total", "warnings"])
    show("Report 2: Events by level and type", report_events_by_level_and_type(),
         ["level", "event_type", "n"])
    show("Report 3: Top source IPs", report_top_source_ips(),
         ["src_ip", "total", "failures"])
    show("Report 4: Authentication failures by user", report_auth_failures_by_user(),
         ["username", "failures", "ips", "first_seen", "last_seen"])
    show("Report 5: AI findings", report_ai_findings(),
         ["severity", "title", "mitre_id", "meaning"])
    show("Report 6: IP reputation (public IPs only)", report_ip_reputation(),
         ["ip", "events", "failures", "verdict", "points"])
    print("\nSummary:", report_summary())
