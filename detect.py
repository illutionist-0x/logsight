import hashlib
from datetime import datetime, timedelta

from db import get_connection
from reports import report_ip_reputation

BURST_MIN_FAILURES = 5
BURST_GAP = timedelta(minutes=10)
SUCCESS_WINDOW = timedelta(minutes=10)
COMPROMISE_WINDOW = timedelta(minutes=60)

LEVELS = ["low", "medium", "high", "critical"]
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_time(text):
    return datetime.strptime(text, TIME_FORMAT)


def bump(level, steps=1):
    return LEVELS[min(LEVELS.index(level) + steps, len(LEVELS) - 1)]


def clean_text(value, limit=40):
    if value is None:
        return None
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text[:limit]


def make_key(rule, host, who, first_seen):
    text = f"{rule}|{host}|{who}|{first_seen}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_events():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, host, event_type, username, src_ip "
            "FROM v_events_full ORDER BY timestamp, id"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def find_bursts(events):
    groups = {}
    for e in events:
        if e["event_type"] == "auth_failure" and e["src_ip"]:
            groups.setdefault((e["host"], e["src_ip"]), []).append(e)

    bursts = []
    for (host, ip), items in groups.items():
        run = [items[0]]
        for e in items[1:]:
            gap = parse_time(e["timestamp"]) - parse_time(run[-1]["timestamp"])
            if gap <= BURST_GAP:
                run.append(e)
            else:
                if len(run) >= BURST_MIN_FAILURES:
                    bursts.append((host, ip, run))
                run = [e]
        if len(run) >= BURST_MIN_FAILURES:
            bursts.append((host, ip, run))
    return bursts


def build_incidents(events, reputation):
    incidents = []
    successes = [e for e in events if e["event_type"] == "login_success"]

    for host, ip, run in find_bursts(events):
        first = run[0]["timestamp"]
        last = run[-1]["timestamp"]
        last_time = parse_time(last)
        follow = [
            s for s in successes
            if s["host"] == host and s["src_ip"] == ip
            and timedelta(0) <= parse_time(s["timestamp"]) - last_time <= SUCCESS_WINDOW
        ]
        users = sorted({clean_text(e["username"]) for e in run if e["username"]})
        verdict = reputation.get(ip, "not checked")

        rule = "brute_force"
        severity = "medium"
        title = f"Brute force against {host} from {ip}"
        if follow:
            rule = "brute_force_success"
            severity = "high"
            title = f"Brute force then successful login on {host} from {ip}"
        if verdict == "malicious":
            severity = bump(severity)

        incidents.append({
            "rule": rule,
            "key": make_key(rule, host, ip, first),
            "title": title,
            "severity": severity,
            "mitre_id": "T1110",
            "technique_name": "Brute Force",
            "host": host,
            "src_ip": ip,
            "first_seen": first,
            "last_seen": follow[0]["timestamp"] if follow else last,
            "facts": {
                "failures": len(run),
                "distinct_usernames": len(users),
                "usernames": users[:10],
                "window_seconds": int((last_time - parse_time(first)).total_seconds()),
                "success_after": bool(follow),
                "successful_user": clean_text(follow[0]["username"]) if follow else None,
                "success_time": follow[0]["timestamp"] if follow else None,
                "ip_reputation": verdict,
            },
            "event_ids": [e["id"] for e in run] + [s["id"] for s in follow],
        })

    compromised = [i for i in incidents if i["rule"] == "brute_force_success"]
    for e in events:
        if e["event_type"] != "user_created":
            continue
        when = parse_time(e["timestamp"])
        related = [
            i for i in compromised
            if i["host"] == e["host"]
            and timedelta(0) <= when - parse_time(i["facts"]["success_time"]) <= COMPROMISE_WINDOW
        ]
        name = clean_text(e["username"]) or "unknown"
        if related:
            rule = "account_created_after_compromise"
            severity = "critical"
            title = f"New account {name} created on {e['host']} after a compromise"
            ids = [e["id"]] + related[0]["event_ids"]
        else:
            rule = "account_created"
            severity = "medium"
            title = f"New local account {name} created on {e['host']}"
            ids = [e["id"]]

        incidents.append({
            "rule": rule,
            "key": make_key(rule, e["host"], name, e["timestamp"]),
            "title": title,
            "severity": severity,
            "mitre_id": "T1136.001",
            "technique_name": "Create Account: Local Account",
            "host": e["host"],
            "src_ip": related[0]["src_ip"] if related else None,
            "first_seen": e["timestamp"],
            "last_seen": e["timestamp"],
            "facts": {
                "new_account": name,
                "after_compromise": bool(related),
                "related_ip": related[0]["src_ip"] if related else None,
            },
            "event_ids": ids,
        })

    incidents.sort(key=lambda i: (-LEVELS.index(i["severity"]), i["first_seen"]))
    return incidents


def ev(n, ts, host, etype, user=None, ip=None):
    return {"id": n, "timestamp": ts, "host": host, "event_type": etype,
            "username": user, "src_ip": ip}


def burst(minute, count, ip="8.8.4.4", host="h1", first_id=1):
    return [ev(first_id + i, f"2026-11-18 10:{minute:02d}:{i:02d}", host,
               "auth_failure", "root", ip) for i in range(count)]


def selftest():
    success = ev(50, "2026-11-18 10:00:09", "h1", "login_success", "root", "8.8.4.4")
    cases = [
        ("4 failures is not a burst", burst(0, 4), {}, []),
        ("5 failures is a burst", burst(0, 5), {}, [("brute_force", "medium")]),
        ("two bursts an hour apart",
         burst(0, 5) + burst(59, 5, first_id=20), {},
         [("brute_force", "medium"), ("brute_force", "medium")]),
        ("burst then success", burst(0, 5) + [success], {},
         [("brute_force_success", "high")]),
        ("malicious IP raises severity", burst(0, 5) + [success],
         {"8.8.4.4": "malicious"}, [("brute_force_success", "critical")]),
        ("new account after compromise",
         burst(0, 5) + [success, ev(60, "2026-11-18 10:20:00", "h1", "user_created", "bob")], {},
         [("brute_force_success", "high"), ("account_created_after_compromise", "critical")]),
        ("new account alone",
         [ev(70, "2026-11-18 10:20:00", "h1", "user_created", "bob")], {},
         [("account_created", "medium")]),
        ("success on another host is not linked",
         burst(0, 5) + [ev(80, "2026-11-18 10:00:09", "h2", "login_success", "root", "8.8.4.4")], {},
         [("brute_force", "medium")]),
    ]
    failed = 0
    for name, events, rep, expected in cases:
        got = sorted((i["rule"], i["severity"]) for i in build_incidents(events, rep))
        ok = got == sorted(expected)
        failed += 0 if ok else 1
        print(f"{'ok' if ok else 'WRONG':5} {name}: expected {sorted(expected)}, got {got}")
    print("All cases passed" if failed == 0 else f"{failed} case(s) failed")
    return failed


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        raise SystemExit(selftest())

    reputation = {r["ip"]: r["verdict"] for r in report_ip_reputation(limit=100000)}
    found = build_incidents(load_events(), reputation)
    print(f"{len(found)} incident(s) found")
    for i in found:
        print(f"[{i['severity']}] {i['rule']}: {i['title']}")
        print(f"    {i['mitre_id']} {i['technique_name']} | "
              f"{i['first_seen']} to {i['last_seen']} | {len(i['event_ids'])} events")
        print(f"    facts: {i['facts']}")