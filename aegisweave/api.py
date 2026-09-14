"""Authenticated local API and bounded, ordered inference worker."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
from pathlib import Path
import queue
import threading
import time

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.datastructures import MutableHeaders

from .auth import Auth
from .response import ActionReason, Policy, ResponseConflict, ResponseEngine, ResponseRequest
from .schema import Flow
from .storage import DuplicateEvent, Store

LOG = logging.getLogger("aegisweave.api")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class SecurityMiddleware:
    """Bounds streamed request bodies before parsing, without trusting Content-Length."""
    def __init__(self, app, auth, max_body=2 * 1024 * 1024):
        self.app, self.auth, self.max_body = app, auth, max_body

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
            await send(message)

        request = Request(scope, receive)
        try:
            self.auth.perimeter(request)
            if scope["path"].startswith("/api/"):
                client = request.client.host if request.client else "unknown"
                self.auth.rate_limit(client, limit=600)
            length = request.headers.get("content-length")
            if length and (not length.isdigit() or int(length) > self.max_body):
                raise HTTPException(413, "Request body exceeds the 2 MiB limit")
            messages, size = [], 0
            if scope["method"] in {"POST", "PUT", "PATCH"}:
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    size += len(message.get("body", b""))
                    if size > self.max_body:
                        raise HTTPException(413, "Request body exceeds the 2 MiB limit")
                    messages.append(message)
                    if not message.get("more_body", False):
                        break

            async def replay():
                return messages.pop(0) if messages else await receive()

            await self.app(scope, replay, secure_send)
        except HTTPException as exc:
            await JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)(scope, receive, secure_send)
        except Exception as exc:
            LOG.error("request_failed path=%s error_type=%s", scope["path"], type(exc).__name__)
            await JSONResponse({"detail": "Service operation failed; consult authenticated health and audit information"}, status_code=503)(scope, receive, secure_send)


class BatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[Flow] = Field(min_length=1, max_length=200)


class DemoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    count: int = Field(default=120, ge=1, le=200)
    seed: int = Field(default=42, ge=0, le=2**32 - 1)


class InferenceWorker:
    def __init__(self, engine, store, capacity=1024):
        self.engine, self.store = engine, store
        self.queue = queue.Queue(maxsize=capacity)
        self.submit_lock = threading.Lock()
        self.metrics_lock = threading.Lock()
        self.running = False
        self.thread = None
        self.processed = self.errors = self.rejected = 0
        self.last_error = None
        self.queue_latency_ms = 0.0
        self.busy = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, name="aegisweave-inference", daemon=True)
        self.thread.start()

    def _run(self):
        while self.running or not self.queue.empty():
            try:
                flow, raw, future, enqueued = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self.metrics_lock:
                self.busy = True
                self.queue_latency_ms = (time.perf_counter() - enqueued) * 1000
            try:
                if self.store.event(flow.event_id) is not None:
                    raise DuplicateEvent("event_id has already been ingested")
                if self.engine is None:
                    raise RuntimeError("ML model is unavailable")
                event = self.engine.process(flow)
                self.store.add_event(event, raw)
                with self.metrics_lock:
                    self.processed += 1
                    self.last_error = None
                if not future.cancelled():
                    future.set_result(event)
            except Exception as exc:
                with self.metrics_lock:
                    if isinstance(exc, DuplicateEvent):
                        self.rejected += 1
                    else:
                        self.errors += 1
                        self.last_error = type(exc).__name__
                LOG.error("inference_failed event_id=%s error_type=%s", flow.event_id, type(exc).__name__)
                try:
                    self.store.audit("system", "telemetry.rejected" if isinstance(exc, DuplicateEvent) else "inference.failed", flow.event_id, {"error_type": type(exc).__name__})
                except Exception:
                    LOG.error("inference_failure_audit_unavailable")
                if not future.cancelled():
                    future.set_exception(exc)
            finally:
                with self.metrics_lock:
                    self.busy = False
                self.queue.task_done()

    def submit(self, items):
        with self.submit_lock:
            if not self.running or not self.thread or not self.thread.is_alive() or self.engine is None:
                raise HTTPException(503, "Inference service is unavailable; load a verified model first")
            if self.queue.qsize() + len(items) > self.queue.maxsize:
                raise HTTPException(429, "Inference queue is full; retry after pending events finish", headers={"Retry-After": "2"})
            futures = []
            for flow, raw in items:
                future = Future()
                self.queue.put_nowait((flow, raw, future, time.perf_counter()))
                futures.append(future)
            return futures

    async def process(self, items):
        futures = self.submit(items)
        results = await asyncio.gather(*(asyncio.wrap_future(f) for f in futures), return_exceptions=True)
        failures = [r for r in results if isinstance(r, Exception)]
        if failures:
            # Batch inference may partially succeed; explicitly report accepted IDs and failures.
            detail = {"message": "One or more events could not be processed", "accepted": len(results) - len(failures),
                      "event_ids": [r["event_id"] for r in results if isinstance(r, dict)],
                      "errors": [{"event_id": flow.event_id, "type": type(result).__name__} for (flow, _), result in zip(items, results) if isinstance(result, Exception)]}
            status = 409 if all(isinstance(r, DuplicateEvent) for r in failures) else 503
            raise HTTPException(status, detail)
        return results

    def health(self):
        with self.metrics_lock:
            return {"status": "healthy" if self.running and self.thread and self.thread.is_alive() else "stopped",
                    "depth": self.queue.qsize(), "capacity": self.queue.maxsize, "busy": self.busy,
                    "processed": self.processed, "errors": self.errors, "rejected": self.rejected, "last_error": self.last_error,
                    "queue_latency_ms": round(self.queue_latency_ms, 3)}

    def stop(self):
        with self.submit_lock:
            self.running = False
        if self.thread:
            self.thread.join(timeout=30)
            if self.thread.is_alive():
                LOG.error("inference_worker_shutdown_timeout")


def create_app(engine=None, db_path="var/aegisweave.db", model_path="var/models/active", tokens=None,
               queue_capacity=1024, store=None):
    """Inject an engine/store for tests; otherwise load a trusted local model at startup."""
    auth = Auth(tokens)
    evidence = store if store is not None else Store(db_path)
    responses = ResponseEngine(evidence)
    worker = InferenceWorker(engine, evidence, capacity=queue_capacity)
    started = time.monotonic()

    async def sweep_expiry():
        while True:
            try:
                await asyncio.to_thread(responses.expire)
            except Exception:
                LOG.exception("response_expiry_failed")
            await asyncio.sleep(1)

    @asynccontextmanager
    async def lifespan(app):
        if worker.engine is None:
            try:
                from .ml import ModelBundle
                from .detection import DetectionEngine
                worker.engine = DetectionEngine(await asyncio.to_thread(ModelBundle.load, Path(model_path)))
            except Exception as exc:
                worker.last_error = type(exc).__name__
                LOG.error("model_load_failed error_type=%s", type(exc).__name__)
                evidence.audit("system", "model.load_failed", "active_model", {"error_type": type(exc).__name__})
        if worker.engine is not None:
            metadata = getattr(worker.engine.model, "metadata", {})
            evidence.register_model(metadata)
            LOG.info("service_started model_version=%s simulated_training=%s auth_mode=%s response_mode=simulation",
                     metadata.get("version", "unavailable"), metadata.get("simulated_training"), "loopback_demo" if auth.demo else "configured_tokens")
        worker.start()
        sweeper = asyncio.create_task(sweep_expiry())
        yield
        sweeper.cancel()
        try:
            await sweeper
        except asyncio.CancelledError:
            pass
        await asyncio.to_thread(worker.stop)
        if store is None and (not worker.thread or not worker.thread.is_alive()):
            evidence.close()

    app = FastAPI(title="AegisWeave", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware, auth=auth)
    app.state.store, app.state.responses, app.state.worker, app.state.auth = evidence, responses, worker, auth
    viewer, analyst, admin = auth.require("viewer"), auth.require("analyst"), auth.require("admin")

    def detailed_health():
        engine_health = worker.engine.health() if worker.engine is not None else {"status": "unavailable", "model": "unavailable"}
        database = evidence.health()
        inference_queue = worker.health()
        return {"status": "healthy" if engine_health.get("status") not in {"unavailable", "error", "degraded"} and database["status"] == "healthy" and inference_queue["status"] == "healthy" and not worker.last_error else "degraded",
                "collector": {"status": "ready", "mode": "normalized telemetry API; synthetic replay available"},
                "inference": engine_health, "database": database, "queue": inference_queue,
                "uptime_seconds": round(time.monotonic() - started, 1), "response_mode": "simulation",
                "auth_mode": "loopback_demo" if auth.demo else "configured_tokens"}

    def found(item, label):
        if item is None:
            raise HTTPException(404, label + " not found")
        return item

    def response_call(function, *args):
        try:
            return function(*args)
        except KeyError:
            raise HTTPException(404, "Event or response not found")
        except ResponseConflict as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/health")
    def health():
        result = detailed_health()
        return {"status": result["status"], "response_mode": "simulation"}

    @app.get("/api/session")
    def session():
        if not auth.demo:
            raise HTTPException(404, "Demo sessions are disabled when authentication is configured")
        return {"token": auth.session_token, "role": "admin", "mode": "loopback_demo"}

    @app.get("/api/identity")
    def identity(user=Depends(viewer)):
        return {"role": user["role"], "mode": "loopback_demo" if auth.demo else "configured_tokens"}

    @app.get("/api/overview")
    def overview(user=Depends(viewer)):
        result = evidence.overview()
        result["health"] = detailed_health()
        return result

    @app.get("/api/events")
    def events(limit: int = Query(100, ge=1, le=500), decision: str = Query("", pattern="^(normal|suspicious|anomalous|malicious|unknown)?$"), search: str = Query("", max_length=128), user=Depends(viewer)):
        return {"items": evidence.events(limit, decision, search)}

    @app.get("/api/events/{event_id}")
    def event(event_id: str, user=Depends(viewer)):
        return found(evidence.event(event_id), "Event")

    @app.get("/api/incidents")
    def incidents(limit: int = Query(100, ge=1, le=500), user=Depends(viewer)):
        return {"items": evidence.incidents(limit)}

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str, user=Depends(viewer)):
        return found(evidence.incident(incident_id), "Incident")

    @app.get("/api/models")
    def models(user=Depends(viewer)):
        metadata = getattr(worker.engine.model, "metadata", {}) if worker.engine else {}
        return {"items": evidence.models(), "active_version": metadata.get("version"), "available": worker.engine is not None}

    @app.get("/api/behavior")
    def behavior(user=Depends(viewer)):
        return {"items": worker.engine.behavior.snapshot() if worker.engine else []}

    @app.get("/api/drift")
    def drift(user=Depends(viewer)):
        return worker.engine.drift_snapshot() if worker.engine else {"status": "unavailable", "window_size": 0}

    @app.get("/api/metrics")
    def metrics(user=Depends(viewer)):
        overview = evidence.overview()
        total = overview["total_events"]
        try:
            import psutil
            process = psutil.Process()
            resources = {"rss_bytes": process.memory_info().rss, "cpu_percent": process.cpu_percent(), "threads": process.num_threads()}
        except (ImportError, OSError):
            resources = {"status": "unavailable"}
        return {"health": detailed_health(), "events_per_second": overview["events_per_second"],
                "inference_latency_ms": overview["inference_latency_ms"], "queue_latency_ms": worker.queue_latency_ms,
                "detection_rate": overview["detected_threats"] / total if total else 0,
                "anomaly_rate": overview["anomalies"] / total if total else 0,
                "alert_rate": (overview["detected_threats"] + overview["suspicious_activity"]) / total if total else 0,
                "response_count": overview["response_actions"], "errors": worker.errors,
                "error_rate": worker.errors / max(1, worker.errors + worker.processed), "resources": resources}

    @app.post("/api/telemetry", status_code=201)
    async def telemetry(flow: Flow, request: Request, user=Depends(analyst)):
        auth.rate_limit(user["actor"] + ":ingest", limit=120)
        return (await worker.process([(flow, await request.json())]))[0]

    @app.post("/api/telemetry/batch", status_code=201)
    async def telemetry_batch(batch: BatchRequest, request: Request, user=Depends(analyst)):
        auth.rate_limit(user["actor"] + ":batch", limit=30)
        raw = (await request.json())["events"]
        result = await worker.process(list(zip(batch.events, raw)))
        return {"accepted": len(result), "events": result}

    @app.post("/api/demo", status_code=201)
    async def demo(options: DemoRequest, user=Depends(analyst)):
        auth.rate_limit(user["actor"] + ":demo", limit=10)
        from .demo import generate_demo
        flows = await asyncio.to_thread(generate_demo, count=options.count, seed=options.seed)
        result = await worker.process([(flow, flow.model_dump(mode="json")) for flow in flows])
        evidence.audit(user["actor"], "demo.replayed", "synthetic_telemetry", {"count": len(result), "seed": options.seed, "simulated": True})
        return {"accepted": len(result), "simulated": True}

    @app.get("/api/policies")
    def policies(user=Depends(viewer)):
        return responses.policy.model_dump()

    @app.put("/api/policies")
    def update_policy(policy: Policy, user=Depends(admin)):
        return responses.update_policy(policy, user["actor"])

    @app.get("/api/responses")
    def response_list(limit: int = Query(100, ge=1, le=500), user=Depends(viewer)):
        responses.expire()
        return {"items": evidence.responses(limit)}

    @app.post("/api/responses", status_code=201)
    def response_propose(body: ResponseRequest, user=Depends(analyst)):
        return response_call(responses.propose, body, user["actor"])

    @app.post("/api/responses/{response_id}/approve")
    def approve_response(response_id: str, body: ActionReason, user=Depends(analyst)):
        return response_call(responses.approve, response_id, user["actor"], body.reason)

    @app.post("/api/responses/{response_id}/rollback")
    def rollback_response(response_id: str, body: ActionReason, user=Depends(analyst)):
        return response_call(responses.rollback, response_id, user["actor"], body.reason)

    @app.get("/api/audit")
    def audit(limit: int = Query(100, ge=1, le=500), user=Depends(analyst)):
        return {"items": evidence.audits(limit)}

    @app.post("/api/models/reload")
    async def reload_model(user=Depends(admin)):
        from .ml import ModelBundle
        from .detection import DetectionEngine
        try:
            model = await asyncio.to_thread(ModelBundle.load, Path(model_path))
            evidence.register_model(model.metadata)
            if worker.engine is None:
                worker.engine = DetectionEngine(model)
            else:
                worker.engine.replace_model(model)
            worker.last_error = None
            evidence.audit(user["actor"], "model.reloaded", str(model.metadata.get("version", "unknown")), {"source": "configured local artifact"})
            return {"status": "loaded", "version": model.metadata.get("version")}
        except Exception as exc:
            evidence.audit(user["actor"], "model.reload_failed", "active_model", {"error_type": type(exc).__name__})
            raise HTTPException(503, "Verified model reload failed; inspect model status before retrying") from exc

    frontend = Path(__file__).resolve().parent.parent / "frontend"
    if frontend.exists():
        app.mount("/static", StaticFiles(directory=str(frontend)), name="static")

    @app.get("/")
    def dashboard():
        index = frontend / "index.html"
        if index.exists():
            return FileResponse(index)
        return JSONResponse({"name": "AegisWeave", "dashboard": "unavailable", "api": "/api/health"})

    return app
