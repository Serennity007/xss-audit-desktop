import io
import json
import unittest
from urllib.error import HTTPError

from xss_audit.research_model import ModelResponder
from xss_audit.agent_audit import audit_repository
from pathlib import Path
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class ResearchModelTests(unittest.TestCase):
    messages = [{"role": "system", "content": "Fixed audit task"}, {"role": "user", "content": "Untrusted repository data"}]

    def test_responses_transport_preserves_roles_and_usage(self):
        def transport(request, timeout):
            body = json.loads(request.data)
            self.assertEqual(body["instructions"], self.messages[0]["content"])
            self.assertEqual(body["input"], self.messages[1:])
            self.assertFalse(body["store"])
            self.assertNotIn("tools", body)
            return io.BytesIO(json.dumps({"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": '{"action":"finish","findings":[]}'}]}], "usage": {"input_tokens": 10, "output_tokens": 4}}).encode())
        responder = ModelResponder("dummy-key", "test-model", transport=transport)
        self.assertEqual(json.loads(responder(self.messages))["action"], "finish")
        self.assertEqual(responder.metadata()["provider_usage"], {"input_tokens": 10, "output_tokens": 4})
        self.assertNotIn("dummy-key", json.dumps(responder.metadata()))

    def test_chat_and_key_echo_masking(self):
        def transport(request, timeout):
            self.assertTrue(request.full_url.endswith("/chat/completions"))
            self.assertEqual(json.loads(request.data)["messages"], self.messages)
            self.assertEqual(json.loads(request.data)["max_completion_tokens"], 3000)
            return io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"dummy-key"}}]}')
        responder = ModelResponder("dummy-key", "test-model", api_format="chat", transport=transport)
        self.assertEqual(responder(self.messages), "[REDACTED_API_KEY]")

    def test_failures_do_not_echo_server_bodies_or_keys(self):
        def transport(request, timeout):
            raise HTTPError(request.full_url, 401, "dummy-key private body", {}, None)
        with self.assertRaisesRegex(ValueError, "HTTP 401") as raised:
            ModelResponder("dummy-key", "test-model", transport=transport)(self.messages)
        self.assertNotIn("dummy-key", str(raised.exception))
        with self.assertRaises(ValueError):
            ModelResponder("dummy-key", "test-model", base_url="http://external.example")

    def test_service_errors_keep_safe_failure_categories_in_agent_trace(self):
        for status in (401, 429):
            def transport(request, timeout):
                raise HTTPError(request.full_url, status, "dummy-key private body", {}, None)
            with tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "example.js").write_text("const x=1;", encoding="utf-8")
                result = audit_repository(directory, ModelResponder("dummy-key", "test-model", transport=transport))
            self.assertEqual(result["status"], "model_error")
            self.assertEqual(result["trace"][-1]["http_status"], status)
            self.assertEqual(result["trace"][-1]["service_error"], "http_error")
            self.assertNotIn("dummy-key", json.dumps(result))

    def test_real_http_roundtrip_to_local_mock_service(self):
        requests = []
        action = '{"action":"finish","findings":[]}'
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                if self.path.endswith("/responses"):
                    data = {"status": "completed", "model": "local-mock", "output": [{"type": "message", "content": [{"type": "output_text", "text": action}]}]}
                else:
                    data = {"model": "local-mock", "choices": [{"finish_reason": "stop", "message": {"content": action}}]}
                payload = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for fmt in ("responses", "chat"):
                responder = ModelResponder("dummy-key", "test-model", f"http://127.0.0.1:{server.server_port}/v1", fmt)
                self.assertEqual(responder(self.messages), action)
                self.assertEqual(responder.metadata()["provider_model_ids"], ["local-mock"])
            self.assertEqual([path for path, _ in requests], ["/v1/responses", "/v1/chat/completions"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
