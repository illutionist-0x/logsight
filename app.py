import os

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

import reports
from db import get_connection, init_db
from ingest import ingest_bytes
from pipeline import run_pipeline as run_in_background

MAX_UPLOAD_BYTES = 10 * 1024 * 1024

init_db()

app = FastAPI(title="LogSight")

UPLOAD_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LogSight</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 560px; margin: 60px auto; padding: 0 16px; }
button { padding: 6px 16px; }
#result { margin-top: 16px; font-weight: 600; }
</style>
</head>
<body>
<h1>LogSight</h1>
<p>Upload a Linux auth log to add its events to the database.</p>
<input type="file" id="file">
<button id="go">Upload</button>
<div id="result"></div>
<p><a href="/dashboard">Open dashboard</a></p>
<script>
document.getElementById("go").addEventListener("click", async () => {
  const out = document.getElementById("result");
  const file = document.getElementById("file").files[0];
  if (!file) { out.textContent = "Choose a file first."; return; }
  const form = new FormData();
  form.append("file", file);
  out.textContent = "Uploading...";
  try {
    const res = await fetch("/api/upload", { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) { out.textContent = "Error: " + data.detail; return; }
    if (data.status === "duplicate_file") {
      out.textContent = data.filename + " was already uploaded (batch " +
        data.batch_id + "). Nothing changed.";
      return;
    }
    let message = data.filename + ": " + data.inserted + " new events, " +
      data.duplicates + " duplicates ignored, " + data.skipped + " lines skipped.";
    if (data.enrichment === "queued") {
      message += " IP reputation checks are running in the background.";
    }
    out.textContent = message;
  } catch (err) {
    out.textContent = "Upload failed: " + err;
  }
});
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def home():
    return UPLOAD_PAGE


@app.get("/health")
def health():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return {"status": "ok", "events": total}


@app.post("/api/upload")
async def upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (limit 10 MB)")
    if not data.strip():
        raise HTTPException(status_code=400, detail="File is empty")
    result = ingest_bytes(data, file.filename)
    if result["status"] == "ok" and result["inserted"] > 0:
        background_tasks.add_task(run_in_background)
        result["enrichment"] = "queued"
    return result


@app.get("/api/reports/top-source-ips")
def top_source_ips():
    return reports.report_top_source_ips()


@app.get("/api/reports/volume-by-hour")
def volume_by_hour():
    return reports.report_volume_by_hour()


@app.get("/api/reports/events-by-level-and-type")
def events_by_level_and_type():
    return reports.report_events_by_level_and_type()


@app.get("/api/reports/auth-failures-by-user")
def auth_failures_by_user():
    return reports.report_auth_failures_by_user()


@app.get("/api/reports/ai-findings")
def ai_findings():
    return reports.report_ai_findings()


@app.get("/api/summary")
def summary():
    return reports.report_summary()


@app.get("/dashboard")
def dashboard():
    return FileResponse(os.path.join(os.path.dirname(__file__), "dashboard.html"))

@app.get("/api/reports/ip-reputation")
def ip_reputation():
    return reports.report_ip_reputation()