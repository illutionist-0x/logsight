import threading
import time

from db import get_connection
from enrich import CACHE_HOURS, get_intel
from intel import LOOKUPS, is_public_ip

PAUSE_SECONDS = 16

_run_lock = threading.Lock()


def find_pending_ips():
    conn = get_connection()
    try:
        counts = conn.execute(
            "SELECT src_ip, COUNT(*) AS n FROM events "
            "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC, src_ip"
        ).fetchall()
        fresh = {
            row["ip"]: row["sources"]
            for row in conn.execute(
                "SELECT ip, COUNT(*) AS sources FROM ip_reputation "
                "WHERE datetime(checked_at) > datetime('now', ?) GROUP BY ip",
                (f"-{CACHE_HOURS} hours",),
            )
        }
    finally:
        conn.close()

    pending = []
    for row in counts:
        ip = row["src_ip"]
        if is_public_ip(ip) and fresh.get(ip, 0) < len(LOOKUPS):
            pending.append(ip)
    return pending


def enrich_pending(max_ips=10, pause=PAUSE_SECONDS):
    pending = find_pending_ips()[:max_ips]
    summary = []
    for i, ip in enumerate(pending):
        out = get_intel(ip)
        summary.append(out)
        used_network = any(not r["cached"] for r in out["results"]) or bool(out["errors"])
        if used_network and i < len(pending) - 1:
            time.sleep(pause)
    return summary


def run_in_background():
    if not _run_lock.acquire(blocking=False):
        print("[enrich] another run is in progress; skipping")
        return
    try:
        waiting = find_pending_ips()
        print(f"[enrich] {len(waiting)} public IP(s) pending")
        for out in enrich_pending():
            print(f"[enrich] {out['ip']}: {out['verdict']} "
                  f"(points {out['points']} from {out['sources']} sources)")
            for e in out["errors"]:
                print(f"[enrich]   error: {e}")
        print("[enrich] done")
    except Exception as err:
        print(f"[enrich] failed: {err.__class__.__name__}: {err}")
    finally:
        _run_lock.release()


if __name__ == "__main__":
    waiting = find_pending_ips()
    print(f"{len(waiting)} public IP(s) need lookups: {waiting}")
    for out in enrich_pending():
        print(f"{out['ip']}: {out['verdict']} (points {out['points']} from {out['sources']} sources)")
        for e in out["errors"]:
            print("  error:", e)
    print("Done")