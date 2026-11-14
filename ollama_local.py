"""Local Ollama client for the Break the Model challenge.

This mirrors the interface of btm.py but talks to a local Ollama server instead
of the Nebius API. The default model is gpt-oss:20b, but you can override it
with the OLLAMA_MODEL environment variable or by passing model=... to chat().

Usage:
    OLLAMA_MODEL=gpt-oss:20b python3 ollama_local.py
    OLLAMA_BASE_URL=http://localhost:11434 python3 - <<'PY'
from ollama_local import chat, new_conversation
conv = new_conversation()
print(chat("Hi! What are your visiting hours?", model="gpt-oss:20b", conversation_id=conv))
PY
"""

import json
import os
import time
import uuid
from pathlib import Path

import requests

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "gpt-oss:20b")
LOG = Path(__file__).parent / "logs" / "ollama_attempts.jsonl"
LOG.parent.mkdir(exist_ok=True)
LAST_TURN_ID = None


def list_models():
    """Return the locally installed Ollama model names."""
    r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=30)
    try:
        data = r.json()
    except ValueError as exc:  # pragma: no cover - defensive fallback
        raise RuntimeError(f"Bad response from Ollama: {r.text}") from exc

    if r.status_code != 200:
        raise RuntimeError(f"Error {r.status_code}: {data}")

    models = data.get("models", [])
    return [m.get("name") for m in models if isinstance(m, dict) and m.get("name")]


def new_conversation():
    return "conv_" + uuid.uuid4().hex[:12]


def chat(message, model=None, conversation_id=None):
    """Send a single message to the local Ollama server.

    The signature matches btm.py so it can be swapped in without changing the
    calling code.
    """
    target_model = model or DEFAULT_MODEL
    conv_id = conversation_id or new_conversation()
    payload = {
        "model": target_model,
        "messages": [{"role": "user", "content": message}],
        "stream": False,
    }

    try:
        r = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=300)
        data = r.json()
        if r.status_code != 200:
            raise RuntimeError(f"Error {r.status_code}: {data}")
        reply = data.get("message", {}).get("content", "")
    except Exception:
        # Fallback for older Ollama installs that do not expose /api/chat.
        generate_payload = {
            "model": target_model,
            "prompt": message,
            "stream": False,
        }
        r = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json=generate_payload, timeout=300)
        try:
            data = r.json()
        except ValueError as exc:  # pragma: no cover - defensive fallback
            raise RuntimeError(f"Bad response from Ollama: {r.text}") from exc
        if r.status_code != 200:
            raise RuntimeError(f"Error {r.status_code}: {data}")
        reply = data.get("response", "")

    with LOG.open("a") as f:
        f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "request": payload, "response": data}) + "\n")

    global LAST_TURN_ID
    LAST_TURN_ID = conv_id
    return reply


if __name__ == "__main__":
    print("Models:", list_models())
    conv = new_conversation()
    print(chat("Hi! What are your visiting hours?", model=DEFAULT_MODEL, conversation_id=conv))
    print("turn_id:", LAST_TURN_ID)
