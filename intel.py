import ipaddress

import requests

import config

TIMEOUT = 30

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_MALICIOUS_AT = 5
VT_SUSPICIOUS_AT = 2

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_MAX_AGE_DAYS = 90
ABUSE_MALICIOUS_AT = 75
ABUSE_SUSPICIOUS_AT = 25

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_SUSPICIOUS_AT = 1


class IntelError(Exception):
    pass


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def check_public(ip):
    if not is_public_ip(ip):
        raise IntelError(f"{ip} is not a public IP address; skipped")


def get_key(name, label):
    key = config.API_KEYS[name]
    if not key:
        raise IntelError(f"{label} key is not set in .env")
    return key


def fetch_json(source, url, headers, params=None):
    try:
        response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
    except requests.RequestException as err:
        raise IntelError(f"{source} request failed: {err.__class__.__name__}")
    if response.status_code in (401, 403):
        raise IntelError(f"{source} rejected the key (HTTP {response.status_code})")
    if response.status_code == 429:
        raise IntelError(f"{source} rate limit reached (HTTP 429); try again later")
    if response.status_code != 200:
        raise IntelError(f"{source} returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError:
        raise IntelError(f"{source} returned a response that is not JSON")


def lookup_virustotal(ip):
    check_public(ip)
    key = get_key("virustotal", "VirusTotal")
    body = fetch_json(
        "VirusTotal", VT_URL.format(ip=ip),
        headers={"x-apikey": key, "Accept": "application/json"},
    )
    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("harmless", "malicious", "suspicious", "undetected"))

    if total == 0:
        score, verdict = None, "unknown"
    else:
        score = round(100 * malicious / total)
        if malicious >= VT_MALICIOUS_AT:
            verdict = "malicious"
        elif malicious + suspicious >= VT_SUSPICIOUS_AT:
            verdict = "suspicious"
        else:
            verdict = "clean"

    return {
        "source": "virustotal",
        "ip": ip,
        "score": score,
        "verdict": verdict,
        "detail": f"{malicious} malicious, {suspicious} suspicious of {total} engines; "
                  f"{attrs.get('as_owner')} ({attrs.get('country')})",
        "raw": {
            "stats": stats,
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "reputation": attrs.get("reputation"),
        },
    }


def lookup_abuseipdb(ip):
    check_public(ip)
    key = get_key("abuseipdb", "AbuseIPDB")
    body = fetch_json(
        "AbuseIPDB", ABUSE_URL,
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": ABUSE_MAX_AGE_DAYS},
    )
    data = body.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    reports = data.get("totalReports", 0)

    if data.get("isWhitelisted"):
        verdict = "clean"
    elif score >= ABUSE_MALICIOUS_AT:
        verdict = "malicious"
    elif score >= ABUSE_SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "source": "abuseipdb",
        "ip": ip,
        "score": score,
        "verdict": verdict,
        "detail": f"abuse confidence {score}%, {reports} reports in {ABUSE_MAX_AGE_DAYS} days; "
                  f"{data.get('isp')} ({data.get('countryCode')})",
        "raw": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "numDistinctUsers": data.get("numDistinctUsers"),
            "isWhitelisted": data.get("isWhitelisted"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "countryCode": data.get("countryCode"),
            "lastReportedAt": data.get("lastReportedAt"),
        },
    }


def lookup_otx(ip):
    check_public(ip)
    if ipaddress.ip_address(ip).version != 4:
        raise IntelError("OTX client supports IPv4 only for now")
    key = get_key("otx", "OTX")
    body = fetch_json(
        "OTX", OTX_URL.format(ip=ip),
        headers={"X-OTX-API-KEY": key, "Accept": "application/json"},
    )
    pulse_info = body.get("pulse_info") or {}
    pulses = pulse_info.get("count", 0)
    names = [
        str(p.get("name"))[:80]
        for p in (pulse_info.get("pulses") or [])[:3]
        if p.get("name")
    ]
    verdict = "suspicious" if pulses >= OTX_SUSPICIOUS_AT else "clean"

    return {
        "source": "otx",
        "ip": ip,
        "score": None,
        "verdict": verdict,
        "detail": f"appears in {pulses} OTX threat pulses; "
                  f"{body.get('country_name')} ({body.get('asn')})",
        "raw": {
            "pulse_count": pulses,
            "sample_pulses": names,
            "reputation": body.get("reputation"),
            "country": body.get("country_name"),
            "asn": body.get("asn"),
        },
    }


LOOKUPS = {
    "virustotal": lookup_virustotal,
    "abuseipdb": lookup_abuseipdb,
    "otx": lookup_otx,
}


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    for name, func in LOOKUPS.items():
        try:
            r = func(target)
            print(f"{name}: {r['verdict']} (score {r['score']}) - {r['detail']}")
        except IntelError as err:
            print(f"{name}: FAILED - {err}")
