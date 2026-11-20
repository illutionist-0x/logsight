import re
from collections import Counter
from datetime import datetime

ASSUMED_YEAR = 2026

LINE_PATTERN = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"([^\s:\[]+)(?:\[(\d+)\])?:\s+"
    r"(.*)$"
)

RULES = [
    ("auth_failure", "warning",
     re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"),
     ("username", "src_ip")),
    ("login_success", "info",
     re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port \d+"),
     ("username", "src_ip")),
    ("invalid_user", "warning",
     re.compile(r"Invalid user (\S+) from (\S+) port \d+"),
     ("username", "src_ip")),
    ("connection_closed", "info",
     re.compile(r"Connection closed by invalid user (\S+) (\S+) port \d+"),
     ("username", "src_ip")),
    ("user_created", "warning",
     re.compile(r"new user: name=([^,\s]+)"),
     ("username",)),
    ("sudo_command", "info",
     re.compile(r"^(\S+) : TTY="),
     ("username",)),
]


def parse_timestamp(text):
    clean = " ".join(text.split())
    parsed = datetime.strptime(f"{ASSUMED_YEAR} {clean}", "%Y %b %d %H:%M:%S")
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def extract_fields(message):
    result = {"event_type": "other", "level": "info", "username": None, "src_ip": None}
    for event_type, level, pattern, names in RULES:
        match = pattern.search(message)
        if match:
            result["event_type"] = event_type
            result["level"] = level
            for name, value in zip(names, match.groups()):
                result[name] = value
            break
    return result


def parse_line(line):
    match = LINE_PATTERN.match(line.strip())
    if not match:
        return None
    timestamp, host, program, pid, message = match.groups()
    result = {
        "timestamp": parse_timestamp(timestamp),
        "host": host,
        "program": program,
        "pid": pid,
        "message": message,
    }
    result.update(extract_fields(message))
    return result


if __name__ == "__main__":
    counts = Counter()
    total = 0
    with open("sample_auth.log", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            r = parse_line(line)
            if r is None:
                counts["UNPARSED"] += 1
                continue
            counts[r["event_type"]] += 1
            print(f"{r['timestamp']}  {r['host']:<7} {r['event_type']:<18} {str(r['username']):<12} {r['src_ip']}")
    print()
    print(f"Total lines: {total}")
    for name, count in sorted(counts.items()):
        print(f"  {name}: {count}")