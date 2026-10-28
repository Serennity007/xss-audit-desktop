"""Small transport adapter for the bounded research agent's JSON protocol."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from . import __version__
from .ai import DEFAULT_BASE_URL, MAX_RESPONSE_BYTES, NoRedirects, validate_endpoint
from .agent_audit import ModelServiceError


class ModelResponder:
    def __init__(self, api_key, model, base_url=DEFAULT_BASE_URL, api_format="responses", *, transport=None):
        self.base_url = validate_endpoint(base_url)
        self.api_key = str(api_key).strip()
        self.model = str(model).strip()
        if not self.api_key or not self.model:
            raise ValueError("AI 审计需要 API Key 和模型名称。")
        if any(ord(char) < 33 or ord(char) > 126 for char in self.api_key):
            raise ValueError("API Key 格式无效：请移除空格、换行或非 ASCII 字符。")
        if api_format not in {"responses", "chat"}:
            raise ValueError("不支持的 AI API 格式。")
        self.api_format = api_format
        self.transport = transport or build_opener(NoRedirects()).open
        self.calls = 0
        self.usage = {}
        self.resolved_models = set()

    def __call__(self, messages):
        if self.api_format == "responses":
            endpoint = self.base_url + "/responses"
            payload = {"model": self.model, "store": False,
                       "instructions": messages[0]["content"], "input": messages[1:],
                       "max_output_tokens": 3000}
        else:
            endpoint = self.base_url + "/chat/completions"
            payload = {"model": self.model, "store": False, "messages": messages, "max_completion_tokens": 3000}
        request = Request(endpoint, data=json.dumps(payload).encode("utf-8"), method="POST",
                          headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json",
                                   "User-Agent": f"XSS-Audit-Desktop/{__version__}"})
        self.calls += 1
        try:
            with self.transport(request, timeout=180) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ModelServiceError("response_too_large")
            data = json.loads(raw)
            if self.api_format == "responses":
                if data.get("status") != "completed":
                    raise ModelServiceError("incomplete_response")
                result = "\n".join(part["text"] for item in data.get("output", [])
                                   if item.get("type") == "message" for part in item.get("content", [])
                                   if part.get("type") == "output_text")
            else:
                choice = data["choices"][0]
                if choice.get("finish_reason") != "stop":
                    raise ModelServiceError("incomplete_response")
                result = choice["message"]["content"]
            if not isinstance(result, str) or not result.strip():
                raise ModelServiceError("empty_response")
            usage = data.get("usage", {})
            if isinstance(data.get("model"), str) and len(data["model"]) <= 200:
                self.resolved_models.add(data["model"].replace(self.api_key, "[REDACTED_API_KEY]"))
            if isinstance(usage, dict):
                for key in ("input_tokens", "output_tokens", "prompt_tokens", "completion_tokens", "total_tokens"):
                    if type(usage.get(key)) is int and usage[key] >= 0:
                        self.usage[key] = self.usage.get(key, 0) + usage[key]
            return result.replace(self.api_key, "[REDACTED_API_KEY]")
        except HTTPError as error:
            raise ModelServiceError("http_error", error.code) from None
        except TimeoutError:
            raise ModelServiceError("timeout") from None
        except URLError as error:
            raise ModelServiceError("timeout" if isinstance(error.reason, TimeoutError) else "connection_error") from None
        except OSError:
            raise ModelServiceError("connection_error") from None
        except (KeyError, IndexError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError):
            raise ModelServiceError("invalid_response") from None

    def metadata(self):
        return {"model": self.model, "base_url": self.base_url, "api_format": self.api_format,
                "calls": self.calls, "provider_usage": dict(self.usage),
                "provider_model_ids": sorted(self.resolved_models),
                "requested_output_token_cap": 3000,
                "usage_notice": "Provider-reported tokens only; absent values are unavailable. No monetary cost is estimated."}
