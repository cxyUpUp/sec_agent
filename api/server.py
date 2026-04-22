import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from eval.export_report import generate_report
from eval.run_eval import evaluate_all
from main import run_agent


class SecAgentHandler(BaseHTTPRequestHandler):
    server_version = "SecAgentHTTP/0.1"

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw) if raw else {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self._send_json({"status": "ok"})
        if path == "/eval":
            return self._send_json(evaluate_all())
        return self._send_json({"error": "not_found"}, status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self._read_json()
        except Exception:
            return self._send_json({"error": "invalid_json"}, status=400)

        if path == "/chat":
            user_id = str(data.get("user_id", "web_user"))
            message = str(data.get("message", ""))
            if not message:
                return self._send_json({"error": "message_required"}, status=400)
            answer, trace = run_agent(message, user_id=user_id, with_trace=True)
            return self._send_json(
                {
                    "answer": answer,
                    "blocked": bool(trace.get("blocked")),
                    "security_trace": trace,
                }
            )

        if path == "/eval/report":
            report_path = generate_report()
            return self._send_json({"report_path": report_path})

        return self._send_json({"error": "not_found"}, status=404)


def run(host="127.0.0.1", port=8080):
    server = HTTPServer((host, port), SecAgentHandler)
    print(f"Sec_Agent backend running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
