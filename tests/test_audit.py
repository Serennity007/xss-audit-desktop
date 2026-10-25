import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from urllib.error import HTTPError

from xss_audit.ai import NoRedirects, review, validate_endpoint
from xss_audit.cli import main
from xss_audit.scanner import LAYERS, MAX_FILE_BYTES, markdown, scan, write_report


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def source(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_all_layers_are_review_signals_with_positions(self):
        signals = ["el.innerHTML = input", "el.setAttribute(name, value)", "window.open(url)",
                   "const state = JSON.stringify(data)", "<a {...props} />", "localStorage.getItem('x')",
                   "merge(target, data)", "eval(input)", "el.style.cssText = style",
                   "<svg><foreignObject /></svg>", "DOMPurify.sanitize(html)",
                   "<div v-html='html' />", "trustedTypes.createPolicy('x', policy)",
                   "ko.applyBindings(vm)"]
        self.source("src/示例.tsx", "\n".join(signals))
        result = scan(self.root)
        self.assertEqual({m.layer for m in result.matches}, set(range(1, 15)))
        self.assertTrue(all(m.status == "待人工确认" for m in result.matches))
        html = next(m for m in result.matches if m.layer == 1)
        self.assertEqual((html.path, html.line, html.column), ("src/示例.tsx", 1, 4))
        self.assertIn("零匹配不代表安全", markdown(result, "zh-CN"))
        self.assertIn("no matches is not proof of safety", markdown(result, "en"))

    def test_exclusions_unread_and_oversize_are_recorded(self):
        self.source("node_modules/pkg/bad.js", "eval(x)")
        self.source("dist/bad.js", "eval(x)")
        self.source("src/app.min.js", "eval(x)")
        self.source(".env", "SECRET=example")
        self.source("big.js", "x" * (MAX_FILE_BYTES + 1))
        (self.root / "invalid.js").write_bytes(b"\xff\xfe")
        (self.root / "binary.js").write_bytes(b"a\x00b")
        self.source("ok.js", "const text = 'safe'")
        result = scan(self.root)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(len(result.matches), 0)
        self.assertEqual(len(result.skipped), 7)

    def test_cancellation_and_limits_are_not_complete(self):
        self.source("app.js", "eval(x)")
        event = threading.Event()
        event.set()
        self.assertTrue(scan(self.root, cancel=event).cancelled)
        with patch("xss_audit.scanner.MAX_MATCHES", 1):
            result = scan(self.root)
        self.assertTrue(result.truncated)
        self.assertIn("不完整", markdown(result, "zh-CN"))
        self.assertIn("incomplete", markdown(result, "en"))

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / "outside.js"
            outside.write_text("eval(secret)", encoding="utf-8")
            try:
                (self.root / "link.js").symlink_to(outside)
            except OSError:
                self.skipTest("Windows symlink permission not available")
            result = scan(self.root)
            self.assertEqual(result.files_scanned, 0)
            self.assertTrue(result.skipped)

    def test_reports_do_not_overwrite_or_dump_whole_files(self):
        self.source("safe.js", "const uniqueWholeFileContent = 123;")
        result = scan(self.root, collect_source=True)
        target = self.root / "report.json"
        write_report(result, target, "json")
        data = json.loads(target.read_text(encoding="utf-8"))
        self.assertNotIn("sources", data)
        self.assertNotIn("uniqueWholeFileContent", target.read_text(encoding="utf-8"))
        with self.assertRaises(FileExistsError):
            write_report(result, target, "json")

    def test_source_budget_uses_complete_files_and_records_omissions(self):
        self.source("a.js", "const a = 1;")
        self.source("b.js", "b" * 1000)
        with patch("xss_audit.scanner.AI_CHAR_BUDGET", 200):
            result = scan(self.root, collect_source=True)
        self.assertEqual([f["path"] for f in result.sources], ["a.js"])
        self.assertEqual(result.ai_omitted, ["b.js"])

    def test_ai_responses_request_and_report(self):
        self.source("app.js", "el.innerHTML = userInput")
        result = scan(self.root, collect_source=True)
        captured = {}

        def transport(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data)
            return io.BytesIO(json.dumps({"status": "completed", "output": [
                {"type": "reasoning"}, {"type": "message", "content": [
                    {"type": "output_text", "text": "待人工确认；mock-secret"}]}]}).encode())
        review(result, "mock-secret", "test-model", transport=transport)
        self.assertTrue(captured["url"].endswith("/v1/responses"))
        self.assertFalse(captured["body"]["store"])
        self.assertIn("app.js", captured["body"]["input"])
        self.assertNotIn("mock-secret", json.dumps(result.to_dict()))
        self.assertEqual(result.ai_metadata["sent_files"], ["app.js"])

    def test_ai_chat_and_incomplete_responses(self):
        self.source("app.js", "eval(input)")
        result = scan(self.root, collect_source=True)
        def chat(request, timeout):
            self.assertTrue(request.full_url.endswith("/chat/completions"))
            return io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"review"}}]}')
        self.assertEqual(review(result, "key", "model", api_format="chat", transport=chat), "review")
        with self.assertRaises(ValueError):
            review(result, "key", "model", transport=lambda *a, **k: io.BytesIO(b'{"status":"incomplete"}'))

    def test_ai_masks_source_values_before_network_request(self):
        secret = "ghp_" + "B" * 36
        self.source("config.json", json.dumps({"api_key": secret}))
        result = scan(self.root, collect_source=True)
        def transport(request, timeout):
            self.assertNotIn(secret.encode(), request.data)
            self.assertIn(b"[REDACTED]", request.data)
            return io.BytesIO(b'{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"review"}]}]}')
        review(result, "dummy-api-key", "mock-model", transport=transport)
        self.assertEqual(result.ai_metadata["masked_values"], 1)
        with self.assertRaises(ValueError) as caught:
            review(result, "line-one\nline-two", "mock-model", transport=transport)
        self.assertNotIn("line-one", str(caught.exception))

    def test_ai_errors_do_not_echo_response_or_key(self):
        self.source("app.js", "eval(input)")
        result = scan(self.root, collect_source=True)
        def error(request, timeout):
            raise HTTPError(request.full_url, 401, "secret body", {}, io.BytesIO(b"secret-key"))
        with self.assertRaisesRegex(ValueError, "HTTP 401") as caught:
            review(result, "secret-key", "model", transport=error)
        self.assertNotIn("secret", str(caught.exception))
        for url in ["http://remote.example/v1", "https://user:pass@example.com", "https://example.com?key=x", "file:///tmp/test"]:
            with self.assertRaises(ValueError):
                validate_endpoint(url)
        self.assertEqual(validate_endpoint("http://localhost:1234/v1/"), "http://localhost:1234/v1")
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.example"))

    def test_ai_real_http_transport_with_local_mock_service(self):
        self.source("app.js", "el.innerHTML = input")
        result = scan(self.root, collect_source=True)
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append((self.path, body, self.headers.get("Authorization")))
                response = ({"status": "completed", "output": [{"type": "message", "content": [
                    {"type": "output_text", "text": "本机模拟审计报告"}]}]} if self.path.endswith("/responses") else
                    {"choices": [{"finish_reason": "stop", "message": {"content": "本机模拟审计报告"}}]})
                raw = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for api_format in ("responses", "chat"):
                    text = review(result, "dummy-local-key", "mock-model", f"http://127.0.0.1:{server.server_port}/v1", api_format)
                    self.assertEqual(text, "本机模拟审计报告")
            finally:
                server.shutdown()
                thread.join(timeout=2)
        self.assertEqual([r[0] for r in received], ["/v1/responses", "/v1/chat/completions"])
        self.assertTrue(all(r[2] == "Bearer dummy-local-key" for r in received))

    def test_cli_exit_codes_export_and_ai_failure_keeps_local_report(self):
        self.source("app.js", "eval(input)")
        output = self.root / "out.json"
        self.assertEqual(main([str(self.root), "-o", str(output), "--format", "json", "--fail-on-match"]), 1)
        self.assertEqual(main([str(self.root), "-o", str(output)]), 2)
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            second = self.root / "ai.md"
            self.assertEqual(main([str(self.root), "--ai", "-o", str(second)]), 2)
        self.assertIn("AI review", second.read_text(encoding="utf-8"))

    def test_cli_incomplete_ast_and_priority_filter_are_explicit(self):
        broken = self.source("broken.py", "def broken(:")
        output = self.root / "incomplete.json"
        self.assertEqual(main([str(self.root), "--format", "json", "-o", str(output)]), 2)
        self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["ast_incomplete"])
        broken.unlink()
        self.source("app.js", "const q=location.hash; el.innerHTML=q;")
        filtered = self.root / "filtered.json"
        self.assertEqual(main([str(self.root), "--format", "json", "--min-priority", "高", "--fail-on-match", "-o", str(filtered)]), 1)
        data = json.loads(filtered.read_text(encoding="utf-8"))
        self.assertTrue(all(item["priority"] == "高" for item in data["matches"]))
        self.assertEqual(data["report_filters"]["min_priority"], "高")


if __name__ == "__main__":
    unittest.main()
