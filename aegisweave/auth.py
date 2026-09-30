"""Small role-token boundary with an explicitly local, ephemeral demo session."""
from __future__ import annotations

from collections import OrderedDict, deque
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


ROLE_LEVEL = {"viewer": 0, "analyst": 1, "admin": 2}


def is_loopback(value):
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return address.ipv4_mapped.is_loopback
        return address.is_loopback
    except ValueError:
        return False


class Auth:
    def __init__(self, tokens=None):
        self.tokens = tokens if tokens is not None else {
            role: value for role in ROLE_LEVEL
            if (value := os.getenv("AEGISWEAVE_" + role.upper() + "_TOKEN"))
        }
        if any(role not in ROLE_LEVEL or not isinstance(token, str) or len(token) < 24 for role, token in self.tokens.items()):
            raise ValueError("Configured role tokens must be distinct strings of at least 24 characters")
        if len(set(self.tokens.values())) != len(self.tokens):
            raise ValueError("Each configured role must have a distinct token")
        self.demo = not self.tokens
        self.public_origin = os.getenv("AEGISWEAVE_PUBLIC_ORIGIN", "").rstrip("/")
        if self.public_origin:
            try:
                public = urlsplit(self.public_origin)
                port = public.port
                valid = (not self.demo and public.scheme == "https" and public.hostname and not public.username
                         and not public.password and not public.path and not public.query and not public.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("AEGISWEAVE_PUBLIC_ORIGIN requires token auth and an HTTPS origin without path or credentials")
        self.session_token = secrets.token_urlsafe(48) if self.demo else None
        self.lock = threading.Lock()
        self.requests = OrderedDict()

    def perimeter(self, request: Request):
        if self.demo:
            client = request.client.host if request.client else ""
            host = request.url.hostname or ""
            if not is_loopback(client) or not (host == "localhost" or is_loopback(host)):
                raise HTTPException(403, "Unconfigured demo mode is available only on loopback with a local Host header")
            if any(header.lower() == "forwarded" or header.lower().startswith("x-forwarded-") for header in request.headers):
                raise HTTPException(403, "Forwarded requests are not allowed in loopback demo mode")
        protected = request.method not in {"GET", "HEAD", "OPTIONS"} or request.url.path == "/api/session"
        if protected:
            if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
                raise HTTPException(403, "Cross-site requests are not allowed")
            origin = request.headers.get("origin")
            if origin:
                try:
                    expected = urlsplit(self.public_origin or str(request.base_url))
                    supplied = urlsplit(origin)
                except ValueError as exc:
                    raise HTTPException(403, "Request Origin is invalid") from exc
                if supplied.scheme not in {"http", "https"} or supplied.netloc != expected.netloc or supplied.scheme != expected.scheme or supplied.path not in {"", "/"} or supplied.query or supplied.fragment or supplied.username:
                    raise HTTPException(403, "Request Origin must match this server")

    def require(self, minimum="viewer"):
        def check(request: Request):
            value = request.headers.get("authorization", "")
            scheme, _, token = value.partition(" ")
            if scheme.lower() != "bearer" or not token or len(token) > 512:
                raise HTTPException(401, "A bearer token is required", headers={"WWW-Authenticate": "Bearer"})
            role = None
            if self.demo and hmac.compare_digest(token.encode(), self.session_token.encode()):
                role = "admin"
            for possible, expected in self.tokens.items():
                if hmac.compare_digest(token.encode(), expected.encode()):
                    role = possible
            if role is None:
                raise HTTPException(401, "Invalid bearer token", headers={"WWW-Authenticate": "Bearer"})
            if ROLE_LEVEL[role] < ROLE_LEVEL[minimum]:
                raise HTTPException(403, "This operation requires the " + minimum + " role")
            actor = role + ":" + hashlib.sha256(token.encode()).hexdigest()[:12]
            request.state.actor = actor
            return {"role": role, "actor": actor}
        return check

    def rate_limit(self, key, limit=240, window=60):
        now = time.monotonic()
        with self.lock:
            history = self.requests.setdefault(key, deque())
            self.requests.move_to_end(key)
            while history and history[0] <= now - window:
                history.popleft()
            if len(history) >= limit:
                raise HTTPException(429, "API request rate limit exceeded", headers={"Retry-After": str(window)})
            history.append(now)
            while len(self.requests) > 4096:
                self.requests.popitem(last=False)
