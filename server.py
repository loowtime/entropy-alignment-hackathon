
import json
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"

def parse_flexible_json_objects(raw_text, source_name):
    events = []
    cleaned = re.sub(r'(?m)^\s*-\s+(?=\{)', '', raw_text)
    cleaned = re.sub(r'(?m)^\s*-?\s*"ts"\s*:', '{"ts":', cleaned)

    decoder = json.JSONDecoder()
    idx = 0
    length = len(cleaned)

    while idx < length:
        next_brace = cleaned.find("{", idx)
        if next_brace == -1:
            break
        try:
            obj, end_idx = decoder.raw_decode(cleaned, next_brace)
            if isinstance(obj, dict):
                obj["_source"] = source_name
                events.append(obj)
            idx = end_idx
        except json.JSONDecodeError:
            line_end = cleaned.find("\n{", next_brace + 1)
            chunk = cleaned[next_brace:] if line_end == -1 else cleaned[next_brace:line_end]
            repaired = re.sub(r'\r?\n\s*-?\s*', r'\\n', chunk).strip()
            try:
                obj = json.loads(repaired)
                if isinstance(obj, dict):
                    obj["_source"] = source_name
                    events.append(obj)
                idx = length if line_end == -1 else line_end
            except json.JSONDecodeError:
                idx = next_brace + 1

    return events

def load_all_json_logs():
    events = []
    candidates = []
    for folder in [LOGS_DIR, BASE_DIR]:
        if folder.exists():
            candidates.extend(sorted(folder.glob("*.json")))
            candidates.extend(sorted(folder.glob("*.jsonl")))

    seen_files = set()
    for filepath in candidates:
        if not filepath.is_file() or filepath.resolve() in seen_files:
            continue
        if filepath.name in {"package.json", "tsconfig.json", "MITIGATION.json"}:
            continue
        seen_files.add(filepath.resolve())

        raw = filepath.read_text(encoding="utf-8", errors="ignore").strip()
        if not raw:
            continue

        if raw.startswith("["):
            try:
                arr = json.loads(raw)
                for item in arr:
                    if isinstance(item, dict):
                        item["_source"] = filepath.name
                        events.append(item)
                continue
            except json.JSONDecodeError:
                pass

        events.extend(parse_flexible_json_objects(raw, filepath.name))

    return events

def load_mitigation_report():
    mitigation_file = BASE_DIR / "MITIGATION.json"
    if mitigation_file.exists():
        try:
            return json.loads(mitigation_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {}

class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def do_GET(self):
        if self.path == "/api/logs":
            payload = json.dumps(load_all_json_logs(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/api/mitigation":
            payload = json.dumps(load_mitigation_report(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
            return
        if self.path == "/":
            self.path = "/index.html"
        return super().do_GET()

if __name__ == "__main__":
    port = 8080
    print(f"🚀 Wikipedia Security Report running at: http://127.0.0.1:{port}", flush=True)
    HTTPServer(("0.0.0.0", port), DashboardHandler).serve_forever()