import json
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen3:4b"


def analyze_log(log_line):
    prompt = (
        "You are a SOC analyst. Reply with JSON only, using keys: "
        "meaning, severity, technique_name, action. "
        "Keep each value under 15 words. "
        "severity must be low, medium or high. "
        f"Log: {log_line}"
    )
    payload = {
        "model": MODEL,
        "think": False,
        "stream": False,
        "format": "json",
        "options": {"num_predict": 150, "temperature": 0},
        "messages": [{"role": "user", "content": prompt}],
    }
    response = requests.post(OLLAMA_URL, json=payload, timeout=600)
    response.raise_for_status()
    text = response.json()["message"]["content"]
    return json.loads(text)


if __name__ == "__main__":
    log = "Failed password for root from 203.0.113.42 port 52144 ssh2"
    print("Analyzing:", log)
    result = analyze_log(log)
    print(json.dumps(result, indent=2))