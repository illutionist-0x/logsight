\# LogSight



Automated log analysis with a local LLM. Upload a Linux auth log in the browser, and LogSight stores the events, checks the source IPs against three threat-intelligence services, detects incidents with rules, and uses a local Qwen3 4B model to explain them. Everything except IP reputation lookups runs on your own machine, and it costs nothing to run.



Built and tested on Windows 11 with Python 3.13 and Ollama.



\## How it works



```

&#x20;browser --upload--> FastAPI --> parser --> SQLite (events, hosts, batches)

&#x20;                                               |

&#x20;       +---------------------------------------+

&#x20;       v

&#x20; IP reputation (VirusTotal, AbuseIPDB, OTX) --> 24 h cache --> consensus verdict

&#x20;       v

&#x20; incident detector (rules) --> findings + evidence links --> MITRE lookup table

&#x20;       v

&#x20; Qwen3 4B via Ollama (explains the computed facts; output is validated)

&#x20;       v

&#x20; dashboard: 5 core reports + IP reputation

```



\*\*Rules decide, the model explains.\*\* Severity, incident detection and MITRE IDs are computed by code, because a 4B model was observed giving wrong technique IDs and inconsistent severities. Qwen3 only writes the plain-English summary and next steps, and its output is rejected if it is malformed, too long, names an ID that code did not assign, or mentions an IP address that is not in the facts. The template text written by code is the fallback.



\## Reports



1\. Log volume by hour, with warnings highlighted

2\. Events by type and level

3\. Top source IPs

4\. Authentication failures by user

5\. Incident findings (severity, MITRE technique, explanation, next steps, and who wrote the text)

6\. IP reputation for public IPs (per-source votes and combined verdict)



\## Quick start (Windows)



1\. Install Python 3.11 or newer and \[Ollama](https://ollama.com), then run `ollama pull qwen3:4b`.

2\. In the project folder:

&#x20;  ```

&#x20;  python -m venv .venv

&#x20;  .\\.venv\\Scripts\\Activate.ps1

&#x20;  pip install -r requirements.txt

&#x20;  ```

3\. Create a `.env` file with your free API keys (VirusTotal, AbuseIPDB, AlienVault OTX):

&#x20;  ```

&#x20;  VT\_API\_KEY=

&#x20;  ABUSEIPDB\_API\_KEY=

&#x20;  OTX\_API\_KEY=

&#x20;  ```

4\. Create the database and start the server:

&#x20;  ```

&#x20;  python db.py

&#x20;  uvicorn app:app --reload --port 8765

&#x20;  ```

5\. Open http://localhost:8765/ to upload a log, and http://localhost:8765/dashboard to view results. `sample\_auth.log` contains a planted attack (brute force, a successful login, then a new account).



\## Security design



\- Only public IP addresses are ever sent to a third party. Private, loopback and reserved addresses are refused before any request is made. Log lines, usernames and hostnames never leave the machine.

\- API keys live in `.env`, which is excluded from version control.

\- Log content is treated as untrusted. SQL uses parameters, the dashboard writes all values with `textContent`, usernames are cleaned and truncated, and the LLM prompt marks them as data.

\- Duplicates are blocked at two levels: a SHA-256 of each uploaded file, and a fingerprint of each event.



\## Database



SQLite in WAL mode, with numbered migrations tracked in `schema\_migrations`. Tables: `events`, `hosts`, `upload\_batches`, `findings`, `finding\_events`, `mitre\_techniques`, `ip\_reputation`. Report queries are stored as views.



\## Tests



```

python run\_tests.py

```



Runs the verdict, detector and narrator-validator self-tests plus database integrity checks (foreign keys, duplicates, schema version, verified MITRE IDs).



\## Known limitations



\- Parses Linux syslog-style auth lines only. The timestamp has no year, so one is assumed (`ASSUMED\_YEAR` in `parser.py`).

\- The upload size limit is checked after the file is read into memory.

\- The background-job lock works within one server process only.

\- Qwen3 4B on a CPU takes about a minute per finding, so narration runs in the background.

\- Free API tiers are rate limited, so lookups are throttled and cached for 24 hours.

\- Reputation thresholds were tuned on a small sample of well-known benign IPs. Where real attacks begin is not calibrated.

\- Detection thresholds (5 failures within 10 minutes) are starting points and are constants in `detect.py`.



\## Roadmap



Windows event log and web server log parsers, an alert channel (email or Telegram), a "re-check this IP" button, authentication for the dashboard, and PostgreSQL support.


## Sample data

The sample_auth*.log files are synthetic. Some use well-known public DNS addresses (for example 8.8.8.8 and 1.1.1.1) as stand-ins for external IPs; those services are not attacking anyone. Reserved documentation addresses (203.0.113.x and similar) are used for the planted attack.
