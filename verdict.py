POINTS = {"malicious": 2, "suspicious": 1, "clean": 0}
CORROBORATING_ONLY = {"otx"}
MALICIOUS_AT = 3
SUSPICIOUS_AT = 2


def combine(results):
    usable = [r for r in results if r.get("verdict") in POINTS]
    voters = [r for r in usable if r["source"] not in CORROBORATING_ONLY]
    helpers = [r for r in usable if r["source"] in CORROBORATING_ONLY]

    if not voters:
        return {"verdict": "unknown", "points": 0, "sources": len(usable), "reasons": []}

    points = sum(POINTS[r["verdict"]] for r in voters)
    counted = list(voters)
    if points >= 1:
        for r in helpers:
            points += POINTS[r["verdict"]]
            counted.append(r)

    if points >= MALICIOUS_AT:
        verdict = "malicious"
    elif points >= SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "clean"

    reasons = [f"{r['source']}: {r['verdict']}" for r in counted if r["verdict"] != "clean"]
    return {
        "verdict": verdict,
        "points": points,
        "sources": len(usable),
        "reasons": reasons,
    }


def fake(source, verdict):
    return {"source": source, "verdict": verdict}


CASES = [
    ("all three clean",
     [fake("virustotal", "clean"), fake("abuseipdb", "clean"), fake("otx", "clean")],
     "clean"),
    ("one malicious only",
     [fake("virustotal", "malicious"), fake("abuseipdb", "clean"), fake("otx", "clean")],
     "suspicious"),
    ("two malicious",
     [fake("virustotal", "malicious"), fake("abuseipdb", "malicious"), fake("otx", "clean")],
     "malicious"),
    ("malicious plus OTX corroboration",
     [fake("virustotal", "malicious"), fake("abuseipdb", "clean"), fake("otx", "suspicious")],
     "malicious"),
    ("lone OTX suspicious is ignored",
     [fake("virustotal", "clean"), fake("abuseipdb", "clean"), fake("otx", "suspicious")],
     "clean"),
    ("abuse suspicious plus OTX corroboration",
     [fake("virustotal", "clean"), fake("abuseipdb", "suspicious"), fake("otx", "suspicious")],
     "suspicious"),
    ("two voters suspicious",
     [fake("virustotal", "suspicious"), fake("abuseipdb", "suspicious"), fake("otx", "clean")],
     "suspicious"),
    ("lone abuse suspicious",
     [fake("virustotal", "clean"), fake("abuseipdb", "suspicious"), fake("otx", "clean")],
     "clean"),
    ("only OTX available",
     [fake("otx", "suspicious")],
     "unknown"),
    ("no results", [], "unknown"),
    ("unknown verdicts ignored",
     [fake("virustotal", "unknown"), fake("abuseipdb", "clean")],
     "clean"),
]


if __name__ == "__main__":
    failed = 0
    for name, results, expected in CASES:
        got = combine(results)["verdict"]
        status = "ok" if got == expected else "WRONG"
        if got != expected:
            failed += 1
        print(f"{status:5} {name}: expected {expected}, got {got}")
    print("All cases passed" if failed == 0 else f"{failed} case(s) failed")