import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VALID_APPLICATION_IDS = {"APP-00001", "APP-00002", "APP-00003"}

VALIDATE_PATH = re.compile(r"^/v1/applications/([^/]+)/validate$")

# When set, /v1 endpoints require "Authorization: Bearer <token>".
TOKEN = os.environ.get("APPID_SERVICE_TOKEN", "")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/healthz":
            return self.send_json(200, {"status": "ok"})

        match = VALIDATE_PATH.match(path)
        if match and not self.authorized():
            return self.send_json(401, {"error": "unauthorized"})
        if match:
            app_id = match.group(1)
            return self.send_json(200, {"application_id": app_id, "valid": app_id in VALID_APPLICATION_IDS})

        self.send_json(404, {"error": "not found"})

    def authorized(self):
        if not TOKEN:
            return True
        return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}")

    def send_json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("appid-service listening on :8080", flush=True)
    server.serve_forever()
