import json

from db import get_connection
from detect import build_incidents, load_events
from reports import report_ip_reputation

TEMPLATE_MODEL = "rules-template"


def template_text(incident):
    facts = incident["facts"]
    rule = incident["rule"]

    if rule in ("brute_force", "brute_force_success"):
        names = ", ".join(facts["usernames"]) or "none"
        meaning = (
            f"{facts['failures']} failed logins against {incident['host']} from "
            f"{incident['src_ip']} within {facts['window_seconds']} seconds, "
            f"trying {facts['distinct_usernames']} usernames ({names})."
        )
        if facts["success_after"]:
            meaning += f" A login then succeeded as '{facts['successful_user']}'."
            action = (
                "Treat the account as compromised: reset its credentials, end active "
                "sessions, block the source IP, and review what the account did after "
                "the login."
            )
        else:
            action = (
                "Block the source IP at the firewall, disable password authentication "
                "for SSH, and check whether any login from this IP succeeded."
            )
    elif rule == "account_created_after_compromise":
        meaning = (
            f"A new local account '{facts['new_account']}' was created on "
            f"{incident['host']} shortly after a successful login that followed a "
            f"brute-force attack from {facts['related_ip']}."
        )
        action = (
            "Disable the new account, treat the host as compromised, and review all "
            "changes made after the successful login."
        )
    else:
        meaning = f"A new local account '{facts['new_account']}' was created on {incident['host']}."
        action = "Confirm the account was authorized. If not, disable it and find out who created it."

    return meaning, action


def save_incidents(incidents):
    conn = get_connection()
    new = updated = unchanged = 0
    try:
        for inc in incidents:
            meaning, action = template_text(inc)
            facts_json = json.dumps(inc["facts"], sort_keys=True)
            row = conn.execute(
                "SELECT id, facts_json, severity FROM findings WHERE incident_key = ?",
                (inc["key"],),
            ).fetchone()

            if row is None:
                cursor = conn.execute(
                    "INSERT INTO findings (incident_key, rule, title, severity, "
                    "technique_name, mitre_id, host, src_ip, first_seen, last_seen, "
                    "facts_json, meaning, action, model, narrated) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'rules-template', 0)",
                    (inc["key"], inc["rule"], inc["title"], inc["severity"],
                     inc["technique_name"], inc["mitre_id"], inc["host"], inc["src_ip"],
                     inc["first_seen"], inc["last_seen"], facts_json, meaning, action),
                )
                finding_id = cursor.lastrowid
                new += 1
            elif row["facts_json"] != facts_json or row["severity"] != inc["severity"]:
                finding_id = row["id"]
                conn.execute(
                    "UPDATE findings SET title = ?, severity = ?, last_seen = ?, "
                    "facts_json = ?, meaning = ?, action = ?, "
                    "model = 'rules-template', narrated = 0 WHERE id = ?",
                    (inc["title"], inc["severity"], inc["last_seen"], facts_json,
                     meaning, action, finding_id),
                )
                updated += 1
            else:
                unchanged += 1
                continue

            conn.execute("DELETE FROM finding_events WHERE finding_id = ?", (finding_id,))
            conn.executemany(
                "INSERT OR IGNORE INTO finding_events (finding_id, event_id) VALUES (?, ?)",
                [(finding_id, event_id) for event_id in inc["event_ids"]],
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {"new": new, "updated": updated, "unchanged": unchanged}


def run_detection():
    reputation = {r["ip"]: r["verdict"] for r in report_ip_reputation(limit=100000)}
    incidents = build_incidents(load_events(), reputation)
    return save_incidents(incidents)


if __name__ == "__main__":
    print("Detection:", run_detection())
    conn = get_connection()
    for r in conn.execute("SELECT * FROM v_findings ORDER BY id"):
        print(f"#{r['id']} [{r['severity']}] {r['title']}")
        print(f"    {r['mitre_id']} {r['mitre_name']} ({r['tactic']}) | "
              f"status={r['status']}, text by {r['model']}")
        print(f"    {r['meaning']}")
        print(f"    Next: {r['action']}")
    conn.close()
