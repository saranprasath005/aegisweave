import os
import subprocess
import sys

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aegisweave.auth import Auth


def request(origin, **extra):
    headers = {"host": "nids.example.org", "origin": origin, **extra}
    return Request({"type": "http", "method": "POST", "scheme": "http", "path": "/api/telemetry",
                    "root_path": "", "query_string": b"", "server": ("api", 8765), "client": ("172.20.0.2", 1234),
                    "headers": [(k.encode(), v.encode()) for k, v in headers.items()]})


def test_trusted_public_origin_supports_tls_proxy_without_trusting_forwarded_headers(monkeypatch):
    monkeypatch.setenv("AEGISWEAVE_PUBLIC_ORIGIN", "https://nids.example.org")
    auth = Auth({"admin": "a" * 32})
    auth.perimeter(request("https://nids.example.org"))
    with pytest.raises(HTTPException):
        auth.perimeter(request("https://attacker.example", **{"x-forwarded-host": "attacker.example", "x-forwarded-proto": "https"}))
    with pytest.raises(HTTPException):
        auth.perimeter(request("http://nids.example.org"))
    monkeypatch.delenv("AEGISWEAVE_PUBLIC_ORIGIN")
    with pytest.raises(HTTPException):
        Auth({"admin": "a" * 32}).perimeter(request("https://nids.example.org", **{"x-forwarded-proto": "https"}))


@pytest.mark.parametrize("origin", ["http://nids.example", "https://user:password@nids.example", "https://nids.example/path", "https://nids.example:bad"])
def test_public_origin_must_be_valid_https_configuration(monkeypatch, origin):
    monkeypatch.setenv("AEGISWEAVE_PUBLIC_ORIGIN", origin)
    with pytest.raises(ValueError):
        Auth({"admin": "a" * 32})


def test_public_origin_cannot_enable_remote_demo(monkeypatch):
    monkeypatch.setenv("AEGISWEAVE_PUBLIC_ORIGIN", "https://nids.example.org")
    with pytest.raises(ValueError):
        Auth({})


def test_deployment_mode_refuses_synthetic_model(bundle_dir):
    env = {k: v for k, v in os.environ.items() if not k.startswith("AEGISWEAVE_")}
    result = subprocess.run([sys.executable, "-m", "aegisweave", "serve", "--port", "0",
                             "--model", str(bundle_dir), "--require-real-model"],
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode != 0
    assert "requires a verified, non-synthetic-trained model" in result.stderr
