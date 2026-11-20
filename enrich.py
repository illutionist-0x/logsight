import json

from db import get_connection
from intel import LOOKUPS, IntelError, is_public_ip
from verdict import combine

CACHE_HOURS = 24


def read_cache(conn, ip, source):
    row = conn.execute(
        "SELECT score, verdict, raw_json, checked_at FROM ip_reputation "
        "WHERE ip = ? AND source = ? "
        "AND datetime(checked_at) > datetime('now', ?)",
        (ip, source, f"-{CACHE_HOURS} hours"),
    ).fetchone()
    if row is None:
        return None
    try:
        stored = json.loads(row["raw_json"] or "{}")
    except ValueError:
        stored = {}
    return {
        "source": source,
        "ip": ip,
        "score": row["score"],
        "verdict": row["verdict"],
        "detail": stored.get("detail"),
        "raw": stored.get("raw"),
        "checked_at": row["checked_at"],
        "cached": True,
    }


def write_cache(conn, result):
    blob = json.dumps({"detail": result["detail"], "raw": result["raw"]})
    conn.execute(
        "INSERT INTO ip_reputation (ip, source, score, verdict, raw_json) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(ip, source) DO UPDATE SET "
        "score = excluded.score, verdict = excluded.verdict, "
        "raw_json = excluded.raw_json, checked_at = CURRENT_TIMESTAMP",
        (result["ip"], result["source"], result["score"], result["verdict"], blob),
    )
    conn.commit()


def get_intel(ip, force=False):
    if not is_public_ip(ip):
        return {"ip": ip, "status": "skipped", "reason": "not a public IP address"}

    conn = get_connection()
    results = []
    errors = []
    try:
        for source, lookup in LOOKUPS.items():
            if not force:
                cached = read_cache(conn, ip, source)
                if cached:
                    results.append(cached)
                    continue
            try:
                fresh = lookup(ip)
            except IntelError as err:
                errors.append(f"{source}: {err}")
                continue
            write_cache(conn, fresh)
            fresh["cached"] = False
            results.append(fresh)
    finally:
        conn.close()

    combined = combine(results)
    combined.update({"ip": ip, "status": "ok", "results": results, "errors": errors})
    return combined


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    out = get_intel(target)
    if out["status"] != "ok":
        print(f"{target}: {out['status']} - {out['reason']}")
    else:
        print(f"{target}: {out['verdict']} (points {out['points']} from {out['sources']} sources)")
        for r in out["results"]:
            tag = "cache" if r["cached"] else "live "
            print(f"  [{tag}] {r['source']}: {r['verdict']} - {r['detail']}")
        for e in out["errors"]:
            print("  error:", e)