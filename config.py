import os

from dotenv import load_dotenv

load_dotenv()

API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY", "").strip(),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
    "otx": os.getenv("OTX_API_KEY", "").strip(),
}


def configured_sources():
    return [name for name, key in API_KEYS.items() if key]


if __name__ == "__main__":
    for name, key in API_KEYS.items():
        status = f"set ({len(key)} characters)" if key else "NOT set"
        print(f"{name}: {status}")