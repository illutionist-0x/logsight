import hashlib
import os
import sys

from db import get_connection, init_db, make_event_hash
from parser import parse_line

INSERT_EVENT_SQL = """
INSERT OR IGNORE INTO events
    (batch_id, host_id, timestamp, program, level, event_type,
     username, src_ip, message, event_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def get_host_id(conn, hostname, cache):
    if hostname not in cache:
        conn.execute("INSERT OR IGNORE INTO hosts (hostname) VALUES (?)", (hostname,))
        row = conn.execute(
            "SELECT id FROM hosts WHERE hostname = ?", (hostname,)
        ).fetchone()
        cache[hostname] = row["id"]
    return cache[hostname]


def ingest_bytes(data, filename="upload.log"):
    init_db()
    filename = os.path.basename(filename or "upload.log")[:200]
    file_hash = hashlib.sha256(data).hexdigest()

    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM upload_batches WHERE sha256 = ?", (file_hash,)
        ).fetchone()
        if existing:
            return {
                "status": "duplicate_file", "batch_id": existing["id"],
                "filename": filename, "inserted": 0, "duplicates": 0, "skipped": 0,
            }

        cursor = conn.execute(
            "INSERT INTO upload_batches (filename, sha256) VALUES (?, ?)",
            (filename, file_hash),
        )
        batch_id = cursor.lastrowid

        host_cache = {}
        inserted = duplicates = skipped = 0
        for line in data.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            r = parse_line(line)
            if r is None:
                skipped += 1
                continue
            host_id = get_host_id(conn, r["host"], host_cache)
            event_hash = make_event_hash(r["timestamp"], r["host"], r["message"])
            result = conn.execute(INSERT_EVENT_SQL, (
                batch_id, host_id, r["timestamp"], r["program"],
                r["level"], r["event_type"], r["username"], r["src_ip"],
                r["message"], event_hash,
            ))
            if result.rowcount == 1:
                inserted += 1
            else:
                duplicates += 1

        if host_cache:
            marks = ",".join("?" * len(host_cache))
            conn.execute(
                "UPDATE hosts SET "
                "first_seen = (SELECT MIN(timestamp) FROM events WHERE host_id = hosts.id), "
                "last_seen = (SELECT MAX(timestamp) FROM events WHERE host_id = hosts.id) "
                f"WHERE id IN ({marks})",
                list(host_cache.values()),
            )
        conn.execute(
            "UPDATE upload_batches SET events_inserted = ?, lines_skipped = ? WHERE id = ?",
            (inserted, skipped, batch_id),
        )
        conn.commit()
        return {
            "status": "ok", "batch_id": batch_id, "filename": filename,
            "inserted": inserted, "duplicates": duplicates, "skipped": skipped,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.log"
    with open(path, "rb") as f:
        data = f.read()
    print(ingest_bytes(data, path))

    conn = get_connection()
    print("Total events:", conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
    print("Batches:", conn.execute("SELECT COUNT(*) FROM upload_batches").fetchone()[0])
    conn.close()