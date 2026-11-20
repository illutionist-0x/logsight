import json

from db import get_connection

conn = get_connection()
rows = conn.execute(
    "SELECT ip, source, score, verdict, raw_json FROM ip_reputation ORDER BY ip, source"
).fetchall()
for r in rows:
    raw = json.loads(r["raw_json"] or "{}").get("raw") or {}
    extra = ""
    if r["source"] == "otx":
        extra = f"pulses={raw.get('pulse_count')}"
    elif r["source"] == "abuseipdb":
        extra = f"reports={raw.get('totalReports')}, users={raw.get('numDistinctUsers')}"
    elif r["source"] == "virustotal":
        extra = f"reputation={raw.get('reputation')}"
    print(f"{r['ip']:<16} {r['source']:<11} {r['verdict']:<10} score={r['score']} {extra}")
conn.close()