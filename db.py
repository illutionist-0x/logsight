import hashlib
import sqlite3

DB_PATH = "logsight.db"

MITRE_SEED = [
    ("T1110", "Brute Force", "Credential Access", "brute force"),
    ("T1110.001", "Password Guessing", "Credential Access", "password guessing"),
    ("T1078", "Valid Accounts", "Multiple", "valid accounts"),
    ("T1136.001", "Create Account: Local Account", "Persistence", "create account"),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
     "Privilege Escalation", "sudo"),
    ("T1021.004", "Remote Services: SSH", "Lateral Movement", "ssh"),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "exfiltration"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     "exploit public-facing"),
]


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def make_event_hash(timestamp, host, message):
    text = f"{timestamp}|{host}|{message}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_statements(conn, statements):
    for sql in statements:
        conn.execute(sql)


def migration_1(conn):
    run_statements(conn, [
        """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            source TEXT,
            level TEXT,
            event_type TEXT,
            username TEXT,
            src_ip TEXT,
            message TEXT NOT NULL,
            ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meaning TEXT,
            severity TEXT,
            technique_name TEXT,
            mitre_id TEXT,
            action TEXT,
            event_ids TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""",
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    ])


def migration_2(conn):
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    if count > 0:
        raise RuntimeError("findings table is not empty; refusing to rebuild it")

    run_statements(conn, [
        """CREATE TABLE upload_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            events_inserted INTEGER NOT NULL DEFAULT 0,
            lines_skipped INTEGER NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL UNIQUE,
            first_seen TEXT,
            last_seen TEXT
        )""",
        """CREATE TABLE mitre_techniques (
            mitre_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            keyword TEXT NOT NULL
        )""",
        "DROP TABLE findings",
        """CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meaning TEXT NOT NULL,
            severity TEXT NOT NULL
                CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            technique_name TEXT,
            mitre_id TEXT REFERENCES mitre_techniques(mitre_id),
            action TEXT,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged', 'closed')),
            model TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE finding_events (
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            PRIMARY KEY (finding_id, event_id)
        )""",
        """CREATE TABLE ip_reputation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            score INTEGER,
            verdict TEXT,
            raw_json TEXT,
            checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (ip, source)
        )""",
        "ALTER TABLE events ADD COLUMN batch_id INTEGER REFERENCES upload_batches(id)",
        "ALTER TABLE events ADD COLUMN host_id INTEGER REFERENCES hosts(id)",
        "ALTER TABLE events ADD COLUMN event_hash TEXT",
    ])

    conn.executemany(
        "INSERT OR IGNORE INTO mitre_techniques (mitre_id, name, tactic, keyword) "
        "VALUES (?, ?, ?, ?)",
        MITRE_SEED,
    )

    conn.execute(
        "INSERT OR IGNORE INTO hosts (hostname, first_seen, last_seen) "
        "SELECT host, MIN(timestamp), MAX(timestamp) FROM events "
        "WHERE host IS NOT NULL GROUP BY host"
    )
    conn.execute(
        "UPDATE events SET host_id = "
        "(SELECT id FROM hosts WHERE hostname = events.host)"
    )
    rows = conn.execute(
        "SELECT id, timestamp, host, message FROM events WHERE event_hash IS NULL"
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE events SET event_hash = ? WHERE id = ?",
            (make_event_hash(row["timestamp"], row["host"], row["message"]), row["id"]),
        )

    run_statements(conn, [
        "CREATE UNIQUE INDEX uq_events_hash ON events(event_hash)",
        "CREATE INDEX idx_events_host_id ON events(host_id)",
        "CREATE INDEX idx_events_batch_id ON events(batch_id)",
        "CREATE INDEX idx_findings_created ON findings(created_at)",
    ])


def migration_3(conn):
    run_statements(conn, [
        """CREATE VIEW v_volume_by_hour AS
        SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour,
               COUNT(*) AS total,
               SUM(level = 'warning') AS warnings
        FROM events
        GROUP BY hour""",
        """CREATE VIEW v_events_by_level_type AS
        SELECT level, event_type, COUNT(*) AS n
        FROM events
        GROUP BY level, event_type""",
        """CREATE VIEW v_top_source_ips AS
        SELECT src_ip,
               COUNT(*) AS total,
               SUM(event_type = 'auth_failure') AS failures
        FROM events
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip""",
        """CREATE VIEW v_auth_failures_by_user AS
        SELECT username,
               COUNT(*) AS failures,
               COUNT(DISTINCT src_ip) AS ips,
               MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen
        FROM events
        WHERE event_type = 'auth_failure'
        GROUP BY username""",
        """CREATE VIEW v_findings AS
        SELECT f.id, f.severity, f.technique_name, f.mitre_id,
               m.name AS mitre_name, m.tactic,
               f.meaning, f.action, f.status, f.created_at
        FROM findings f
        LEFT JOIN mitre_techniques m ON m.mitre_id = f.mitre_id""",
        """CREATE VIEW v_summary AS
        SELECT (SELECT COUNT(*) FROM events) AS events,
               (SELECT COUNT(*) FROM events WHERE level = 'warning') AS warnings,
               (SELECT COUNT(*) FROM events WHERE event_type = 'auth_failure') AS auth_failures,
               (SELECT COUNT(*) FROM hosts) AS hosts,
               (SELECT COUNT(*) FROM findings) AS findings""",
    ])


def migration_4(conn):
    version = tuple(int(x) for x in sqlite3.sqlite_version.split("."))
    if version < (3, 35, 0):
        raise RuntimeError(
            f"SQLite {sqlite3.sqlite_version} is too old for DROP COLUMN (need 3.35+)"
        )
    run_statements(conn, [
        "ALTER TABLE events RENAME COLUMN source TO program",
        "ALTER TABLE events DROP COLUMN host",
        """CREATE VIEW v_events_full AS
        SELECT e.id, e.timestamp, h.hostname AS host, e.program, e.level,
               e.event_type, e.username, e.src_ip, e.message, e.batch_id
        FROM events e
        LEFT JOIN hosts h ON h.id = e.host_id""",
    ])


def migration_5(conn):
    run_statements(conn, [
        "ALTER TABLE findings ADD COLUMN incident_key TEXT",
        "ALTER TABLE findings ADD COLUMN rule TEXT",
        "ALTER TABLE findings ADD COLUMN title TEXT",
        "ALTER TABLE findings ADD COLUMN host TEXT",
        "ALTER TABLE findings ADD COLUMN src_ip TEXT",
        "ALTER TABLE findings ADD COLUMN first_seen TEXT",
        "ALTER TABLE findings ADD COLUMN last_seen TEXT",
        "ALTER TABLE findings ADD COLUMN facts_json TEXT",
        "ALTER TABLE findings ADD COLUMN narrated INTEGER NOT NULL DEFAULT 0",
        "CREATE UNIQUE INDEX uq_findings_key ON findings(incident_key)",
        "DROP VIEW v_findings",
        """CREATE VIEW v_findings AS
        SELECT f.id, f.title, f.severity, f.rule, f.technique_name, f.mitre_id,
               m.name AS mitre_name, m.tactic, f.host, f.src_ip,
               f.first_seen, f.last_seen, f.meaning, f.action, f.status,
               f.model, f.narrated, f.created_at
        FROM findings f
        LEFT JOIN mitre_techniques m ON m.mitre_id = f.mitre_id""",
    ])


MIGRATIONS = [
    (1, "initial events and findings tables", migration_1),
    (2, "v2 schema: batches, hosts, MITRE lookup, finding links, IP reputation", migration_2),
    (3, "report views", migration_3),
    (4, "clean up events columns, add v_events_full", migration_4),
    (5, "findings: incident key, rule, facts, time range; refresh v_findings", migration_5),
]


def current_version(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "version INTEGER PRIMARY KEY, "
        "description TEXT, "
        "applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    conn.commit()
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return row[0] or 0


def init_db():
    conn = get_connection()
    version = current_version(conn)
    for number, description, func in MIGRATIONS:
        if number <= version:
            continue
        conn.execute("BEGIN")
        try:
            func(conn)
            conn.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                (number, description),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            conn.close()
            raise
        print(f"Applied migration {number}: {description}")
    conn.close()


if __name__ == "__main__":
    init_db()
    conn = get_connection()
    print("Database ready:", DB_PATH)
    print("Schema version:", current_version(conn))
    names = [r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )]
    print("Tables:", names)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)")]
    print("Findings columns:", cols)
    counts = []
    for t in ["events", "hosts", "upload_batches", "mitre_techniques", "findings"]:
        n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        counts.append(f"{t}={n}")
    print("Row counts:", ", ".join(counts))
    conn.close()