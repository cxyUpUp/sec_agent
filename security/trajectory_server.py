"""Optional OpenAI-compatible server for AgentDoG 1.5 0.8B.

The live guard uses security/trajectory_model.json. This server is for a
machine that can run Qwen3.5. On this CPU the reference linear-attention
kernels do not finish a judgment in time, so the guard does not call it.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOST = os.environ.get("TRAJECTORY_HOST", "127.0.0.1")
PORT = int(os.environ.get("TRAJECTORY_PORT", "8765"))
MODEL_ID = os.environ.get("TRAJECTORY_MODEL", "AI45Research/AgentDoG1.5-Qwen3.5-0.8B")
MODEL_DIR = Path(
    os.environ.get(
        "TRAJECTORY_MODEL_DIR",
        str(Path(__file__).resolve().parents[1] / "models" / "AgentDoG1.5-Qwen3.5-0.8B"),
    )
)
MAX_NEW_TOKENS = int(os.environ.get("TRAJECTORY_MAX_NEW_TOKENS", "280"))

_tokenizer = None
_model = None


def _load():
    global _tokenizer, _model
    if _model is not None:
        return
    os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    source = str(MODEL_DIR if (MODEL_DIR / "config.json").is_file() else MODEL_ID)
    _tokenizer = AutoTokenizer.from_pretrained(source, trust_remote_code=True)
    _model = AutoModelForCausalLM.from_pretrained(
        source,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
        trust_remote_code=True,
    )
    _model.eval()


def _generate(prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
    _load()
    import torch

    messages = [{"role": "user", "content": prompt}]
    try:
        text = _tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=False,
        )
    except TypeError:
        text = _tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
    inputs = _tokenizer(text, return_tensors="pt")
    with torch.no_grad():
        output = _model.generate(
            **inputs,
            max_new_tokens=max(8, min(max_new_tokens, MAX_NEW_TOKENS)),
            do_sample=False,
        )
    new_tokens = output[0][inputs["input_ids"].shape[-1] :]
    return _tokenizer.decode(new_tokens, skip_special_tokens=True).strip()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(fmt % args, flush=True)

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/health":
            self._send(200, {"status": "ok", "model": MODEL_ID, "loaded": _model is not None})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8"))
            messages = request.get("messages") or []
            prompt = str(messages[-1].get("content") or "")
            limit = int(request.get("max_tokens") or MAX_NEW_TOKENS)
            content = _generate(prompt, limit)
        except Exception as exc:  # surface the failure to the guard client
            self._send(500, {"error": type(exc).__name__})
            print(f"generation failed: {type(exc).__name__}: {exc}", flush=True)
            return
        self._send(
            200,
            {
                "model": MODEL_ID,
                "choices": [{"message": {"role": "assistant", "content": content}}],
            },
        )


def main() -> None:
    _load()
    server = ThreadingHTTPServer((HOST, PORT), _Handler)
    print(f"trajectory model ready at http://{HOST}:{PORT}/v1 model={MODEL_ID}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
