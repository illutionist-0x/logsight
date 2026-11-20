import subprocess
import sys

from db import get_connection

SCRIPTS = [
    ("verdict rules", ["verdict.py"]),
    ("incident detector", ["detect.py", "test"]),
    ("narrator validator", ["narrate.py", "test"]),
]


def script_passes(args):
    result = subprocess.run([sys.executable] + args, capture_output=True, text=True)
    return result.returncode == 0 and "All cases passed" in result.stdout


def database_checks():
    conn = get_connection()
    try:
        version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        one = lambda sql: conn.execute(sql).fetchone()[0]
        return [
            ("database integrity", one("PRAGMA integrity_check") == "ok"),
            ("foreign keys consistent", len(conn.execute("PRAGMA foreign_key_check").fetchall()) == 0),
            (f"schema version 5 (found {version})", version == 5),
            ("no duplicate incidents", one(
                "SELECT COUNT(*) FROM (SELECT 1 FROM findings GROUP BY incident_key HAVING COUNT(*) > 1)") == 0),
            ("no duplicate events", one(
                "SELECT COUNT(*) FROM (SELECT 1 FROM events GROUP BY event_hash HAVING COUNT(*) > 1)") == 0),
            ("every MITRE ID is in the verified table", one(
                "SELECT COUNT(*) FROM findings WHERE mitre_id IS NOT NULL AND mitre_id NOT IN "
                "(SELECT mitre_id FROM mitre_techniques)") == 0),
        ]
    finally:
        conn.close()


if __name__ == "__main__":
    results = [(name, script_passes(args)) for name, args in SCRIPTS]
    results += database_checks()
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    failed = sum(1 for _, ok in results if not ok)
    print("\nAll checks passed" if failed == 0 else f"\n{failed} check(s) failed")
    raise SystemExit(1 if failed else 0)