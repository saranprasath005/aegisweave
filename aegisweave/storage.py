"""SQLite evidence store. All statements are parameterized; identities never become SQL."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


class DuplicateEvent(ValueError):
    pass


class Store:
    """One-process WAL store with atomic evidence/incident writes and bounded retention."""

    def __init__(self, path="var/aegisweave.db", max_events=100000, retention_days=30,
                 correlation_seconds=300, max_audit=100000):
        self.path = str(path)
        if self.path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.max_events = max(1, int(max_events))
        self.retention_days = max(1, int(retention_days))
        self.correlation_seconds = max(1, int(correlation_seconds))
        self.max_audit = max(1, int(max_audit))
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA busy_timeout=5000")
            self._migrate()

    def _migrate(self):
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > 2:
            raise RuntimeError("Database schema is newer than this application")
        if version == 0:
            self.db.executescript("""
            BEGIN;
            CREATE TABLE events (
              id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_epoch REAL NOT NULL,
              received_at TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL,
              sensor_id TEXT NOT NULL, simulated INTEGER NOT NULL,
              decision TEXT NOT NULL, class TEXT NOT NULL, confidence REAL NOT NULL,
              anomaly INTEGER NOT NULL, risk REAL NOT NULL, severity TEXT NOT NULL,
              inference_ms REAL NOT NULL, raw_json TEXT NOT NULL, telemetry_json TEXT NOT NULL,
              result_json TEXT NOT NULL);
            CREATE INDEX events_time ON events(event_epoch DESC);
            CREATE INDEX events_source_time ON events(source,event_epoch DESC);
            CREATE INDEX events_decision_time ON events(decision,event_epoch DESC);
            CREATE INDEX events_received ON events(received_at);
            CREATE TABLE incidents (
              id TEXT PRIMARY KEY, source TEXT NOT NULL, sensor_id TEXT NOT NULL,
              simulated INTEGER NOT NULL, first_epoch REAL NOT NULL, last_epoch REAL NOT NULL,
              status TEXT NOT NULL DEFAULT 'open');
            CREATE INDEX incident_correlation ON incidents(source,sensor_id,simulated,last_epoch);
            CREATE TABLE incident_events (
              incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
              event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
              PRIMARY KEY(incident_id,event_id));
            CREATE TABLE responses (
              id TEXT PRIMARY KEY, event_id TEXT NOT NULL, status TEXT NOT NULL,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL, data_json TEXT NOT NULL);
            CREATE INDEX response_expiry ON responses(status,expires_at);
            CREATE TABLE audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
              actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
              details_json TEXT NOT NULL);
            CREATE INDEX audit_time ON audit(timestamp DESC);
            CREATE TABLE settings (key TEXT PRIMARY KEY,value_json TEXT NOT NULL);
            CREATE TABLE models (version TEXT PRIMARY KEY, registered_at TEXT NOT NULL, metadata_json TEXT NOT NULL);
            PRAGMA user_version=1;
            COMMIT;
            """)
            version = 1
        if version == 1:
            self.db.executescript("""
            BEGIN;
            ALTER TABLE models RENAME TO models_v1;
            CREATE TABLE models (model_key TEXT PRIMARY KEY, version TEXT NOT NULL,
                                 registered_at TEXT NOT NULL, metadata_json TEXT NOT NULL);
            INSERT INTO models SELECT COALESCE(json_extract(metadata_json,'$.artifact_sha256'),
                json_extract(metadata_json,'$.training_fingerprint'),json_extract(metadata_json,'$.id'),version),
                version,registered_at,metadata_json FROM models_v1;
            DROP TABLE models_v1;
            CREATE INDEX models_version ON models(version);
            PRAGMA user_version=2;
            COMMIT;
            """)

    def add_event(self, event: dict, raw: dict | None = None) -> dict:
        stamp = str(event["timestamp"])
        epoch = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
        telemetry = event.get("telemetry", {})
        # The stored class is the analyst-facing attribution; a withheld raw model class
        # remains available inside result_json but never drives search or incident labels.
        label = (event.get("attribution") or {}).get("label") or event["prediction"]["class"]
        values = (event["event_id"], stamp, epoch, utc_now(), event["source"],
                  event["destination"], event.get("sensor_id", "local"),
                  int(event.get("simulated", False)), event["fusion"]["decision"],
                  label, event["prediction"]["confidence"],
                  int(event["anomaly"]["is_anomalous"]), event["risk"]["score"],
                  event["risk"]["severity"], event.get("inference_ms", 0),
                  encode(raw if raw is not None else telemetry), encode(telemetry), encode(event))
        with self.lock, self.db:
            try:
                self.db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
            except sqlite3.IntegrityError as exc:
                raise DuplicateEvent("event_id has already been ingested") from exc
            if event["fusion"]["decision"] != "normal":
                self._correlate(event, epoch)
            self._prune()
        return event

    def _correlate(self, event, epoch):
        # Event time, source, sensor, and simulation boundary are correlation evidence.
        # Late events can join only an incident whose interval is within the window.
        rows = self.db.execute(
            "SELECT id FROM incidents WHERE source=? AND sensor_id=? AND simulated=? "
            "AND first_epoch<=? AND last_epoch>=? ORDER BY last_epoch DESC",
            (event["source"], event.get("sensor_id", "local"), int(event.get("simulated", False)),
             epoch + self.correlation_seconds, epoch - self.correlation_seconds)).fetchall()
        incident_id = rows[0]["id"] if rows else str(uuid.uuid4())
        if not rows:
            self.db.execute("INSERT INTO incidents (id,source,sensor_id,simulated,first_epoch,last_epoch) VALUES (?,?,?,?,?,?)",
                            (incident_id, event["source"], event.get("sensor_id", "local"),
                             int(event.get("simulated", False)), epoch, epoch))
        elif len(rows) > 1:
            # A bridging event merges connected event-time intervals atomically.
            for row in rows[1:]:
                self.db.execute("INSERT OR IGNORE INTO incident_events SELECT ?,event_id FROM incident_events WHERE incident_id=?", (incident_id, row["id"]))
                self.db.execute("DELETE FROM incidents WHERE id=?", (row["id"],))
        self.db.execute("INSERT INTO incident_events VALUES (?,?)", (incident_id, event["event_id"]))
        self.db.execute("UPDATE incidents SET first_epoch=(SELECT MIN(e.event_epoch) FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=?),last_epoch=(SELECT MAX(e.event_epoch) FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=?) WHERE id=?", (incident_id, incident_id, incident_id))

    def _prune(self):
        deleted = self.db.execute("DELETE FROM events WHERE received_at < strftime('%Y-%m-%dT%H:%M:%f+00:00','now',?)", (f"-{self.retention_days} days",)).rowcount
        deleted += self.db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY received_at DESC,rowid DESC LIMIT -1 OFFSET ?)", (self.max_events,)).rowcount
        self.db.execute("DELETE FROM incidents WHERE NOT EXISTS (SELECT 1 FROM incident_events WHERE incident_id=incidents.id)")
        if deleted:
            self.db.execute("UPDATE incidents SET first_epoch=(SELECT MIN(e.event_epoch) FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=incidents.id),last_epoch=(SELECT MAX(e.event_epoch) FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=incidents.id)")
        # Audit and response records have independent caps; evidence deletion does not remove audits.
        self.db.execute("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id DESC LIMIT -1 OFFSET ?)", (self.max_audit,))
        self.db.execute("DELETE FROM responses WHERE status IN ('expired','rolled_back','denied') AND id IN (SELECT id FROM responses ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (self.max_audit,))

    def prune(self):
        with self.lock, self.db:
            self._prune()

    def event(self, event_id):
        with self.lock:
            row = self.db.execute("SELECT result_json,raw_json FROM events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            return None
        item = json.loads(row["result_json"])
        item["raw_telemetry"] = json.loads(row["raw_json"])
        return item

    def events(self, limit=100, decision="", search=""):
        clauses, params = [], []
        if decision:
            clauses.append("decision=?")
            params.append(decision)
        if search:
            # Literal search: escape SQL LIKE metacharacters as well as binding values.
            literal = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(source LIKE ? ESCAPE '\\' OR destination LIKE ? ESCAPE '\\' OR class LIKE ? ESCAPE '\\')")
            params.extend([f"%{literal}%"] * 3)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.lock:
            rows = self.db.execute("SELECT result_json FROM events" + where + " ORDER BY event_epoch DESC,rowid DESC LIMIT ?", [*params, min(max(1, int(limit)), 500)]).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _incident(self, row):
        items = self.db.execute("SELECT e.id,e.timestamp,e.event_epoch,e.class,e.decision,e.risk,e.severity FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=? ORDER BY e.event_epoch DESC LIMIT 200", (row["id"],)).fetchall()[::-1]
        if not items:
            return None
        summary = self.db.execute("SELECT COUNT(*) AS n,MIN(e.timestamp) AS first_seen,MAX(e.timestamp) AS last_seen,MAX(e.risk) AS risk FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=?", (row["id"],)).fetchone()
        classes = [x[0] for x in self.db.execute("SELECT DISTINCT e.class FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=? ORDER BY e.class", (row["id"],))]
        severity = "critical" if summary["risk"] >= 85 else "high" if summary["risk"] >= 70 else "medium" if summary["risk"] >= 40 else "low"
        return {"id": row["id"], "source": row["source"], "sensor_id": row["sensor_id"],
                "simulated": bool(row["simulated"]), "title": f"Related activity from {row['source']}",
                "status": row["status"], "severity": severity, "risk_score": summary["risk"],
                "event_count": summary["n"], "first_seen": summary["first_seen"], "last_seen": summary["last_seen"],
                "timeline_truncated": summary["n"] > len(items),
                "classes": classes, "events": [x["id"] for x in items],
                "timeline": [{"event_id": x["id"], "timestamp": x["timestamp"], "decision": x["decision"], "class": x["class"], "risk": x["risk"]} for x in items],
                "explanation": [f"{summary['n']} non-normal events share source, sensor and simulation status within linked {self.correlation_seconds}-second event-time windows.",
                                "Correlation groups evidence; it does not establish a confirmed intrusion or attack progression."]}

    def incidents(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT * FROM incidents ORDER BY last_epoch DESC LIMIT ?", (min(max(int(limit), 1), 500),)).fetchall()
            return [item for row in rows if (item := self._incident(row))]

    def incident(self, incident_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            return self._incident(row) if row else None

    def overview(self):
        with self.lock:
            row = self.db.execute("SELECT COUNT(*) AS total_events,COALESCE(SUM(decision='malicious'),0) AS detected_threats,COALESCE(SUM(anomaly),0) AS anomalies,COALESCE(SUM(decision IN ('suspicious','unknown','anomalous')),0) AS suspicious_activity,COALESCE(SUM(decision='anomalous'),0) AS anomalous_unattributed,COALESCE(SUM(decision='unknown'),0) AS uncertain,COALESCE(AVG(inference_ms),0) AS inference_latency_ms FROM events").fetchone()
            result = dict(row)
            result["decisions"] = {name: 0 for name in ("normal", "suspicious", "anomalous", "malicious", "unknown")}
            result["decisions"].update({x[0]: x[1] for x in self.db.execute("SELECT decision,COUNT(*) FROM events GROUP BY decision")})
            result["critical_incidents"] = self.db.execute("SELECT COUNT(DISTINCT ie.incident_id) FROM incident_events ie JOIN events e ON e.id=ie.event_id WHERE e.severity='critical'").fetchone()[0]
            result["response_actions"] = self.db.execute("SELECT COUNT(*) FROM responses WHERE status='simulated'").fetchone()[0]
            result["events_per_second"] = self.db.execute("SELECT COUNT(*) / 60.0 FROM events WHERE received_at>=strftime('%Y-%m-%dT%H:%M:%f+00:00','now','-60 seconds')").fetchone()[0]
            result["attack_classes"] = [dict(x) for x in self.db.execute("SELECT class AS name,COUNT(*) AS count FROM events GROUP BY class ORDER BY count DESC")]
            result["confidence_distribution"] = [dict(x) for x in self.db.execute("SELECT CASE WHEN confidence<0.5 THEN '0–50%' WHEN confidence<0.7 THEN '50–70%' WHEN confidence<0.9 THEN '70–90%' ELSE '90–100%' END AS name,COUNT(*) AS count FROM events GROUP BY name ORDER BY MIN(confidence)")]
            result["trend"] = [dict(x) for x in self.db.execute("SELECT strftime('%Y-%m-%dT%H:%M:00Z',event_epoch,'unixepoch') AS timestamp,SUM(decision='normal') AS normal,SUM(decision='suspicious') AS suspicious,SUM(decision='malicious') AS malicious,SUM(decision='anomalous') AS anomalous,SUM(decision='unknown') AS unknown FROM events GROUP BY timestamp ORDER BY timestamp DESC LIMIT 60")][::-1]
        result["mode"] = "simulation"
        return result

    def setting(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", (key, encode(value)))

    def save_response(self, item):
        with self.lock, self.db:
            self.db.execute("INSERT INTO responses VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,expires_at=excluded.expires_at,data_json=excluded.data_json", (item["id"], item["event_id"], item["status"], item["created_at"], item["expires_at"], encode(item)))

    def record_response(self, item, actor, action, details):
        """Commit the response transition and its audit entry in the same transaction."""
        with self.lock, self.db:
            self.db.execute("INSERT INTO responses VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,expires_at=excluded.expires_at,data_json=excluded.data_json", (item["id"], item["event_id"], item["status"], item["created_at"], item["expires_at"], encode(item)))
            self.db.execute("INSERT INTO audit(timestamp,actor,action,target,details_json) VALUES (?,?,?,?,?)", (utc_now(), actor, action, item["id"], encode(details)))
            self.db.execute("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id DESC LIMIT -1 OFFSET ?)", (self.max_audit,))

    def record_policy(self, policy, actor, before):
        with self.lock, self.db:
            self.db.execute("INSERT INTO settings VALUES ('response_policy',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", (encode(policy),))
            self.db.execute("INSERT INTO audit(timestamp,actor,action,target,details_json) VALUES (?,?,?,?,?)", (utc_now(), actor, "policy.updated", "response_policy", encode({"before": before, "after": policy})))
            self.db.execute("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id DESC LIMIT -1 OFFSET ?)", (self.max_audit,))

    def response(self, response_id):
        with self.lock:
            row = self.db.execute("SELECT data_json FROM responses WHERE id=?", (response_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def responses(self, limit=100):
        with self.lock:
            return [json.loads(x[0]) for x in self.db.execute("SELECT data_json FROM responses ORDER BY created_at DESC LIMIT ?", (min(max(int(limit), 1), 500),))]

    def active_responses(self):
        with self.lock:
            return [json.loads(x[0]) for x in self.db.execute("SELECT data_json FROM responses WHERE status IN ('simulated','pending_approval')")]

    def audit(self, actor, action, target, details=None):
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit(timestamp,actor,action,target,details_json) VALUES (?,?,?,?,?)", (utc_now(), actor, action, target, encode(details or {})))
            self.db.execute("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id DESC LIMIT -1 OFFSET ?)", (self.max_audit,))

    def audits(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (min(max(int(limit), 1), 500),)).fetchall()
        return [{**{k: row[k] for k in ("id", "timestamp", "actor", "action", "target")}, "details": json.loads(row["details_json"])} for row in rows]

    def recent_actions(self, action, since):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM audit WHERE action=? AND timestamp>=?", (action, since)).fetchone()[0]

    def register_model(self, metadata, artifact_sha256=None):
        metadata = {**metadata, **({"artifact_sha256": artifact_sha256} if artifact_sha256 else {})}
        identity = metadata.get("artifact_sha256") or metadata.get("training_fingerprint") or metadata.get("id") or metadata.get("version", "unknown")
        with self.lock, self.db:
            self.db.execute("INSERT INTO models VALUES (?,?,?,?) ON CONFLICT(model_key) DO UPDATE SET metadata_json=excluded.metadata_json", (str(identity), str(metadata.get("version", "unknown")), utc_now(), encode(metadata)))

    def models(self):
        with self.lock:
            return [json.loads(x[0]) for x in self.db.execute("SELECT metadata_json FROM models ORDER BY registered_at DESC LIMIT 20")]

    def health(self):
        try:
            with self.lock:
                self.db.execute("SELECT 1").fetchone()
                count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            return {"status": "healthy", "engine": "sqlite", "schema_version": 2, "retained_events": count,
                    "max_events": self.max_events, "retention_days": self.retention_days}
        except sqlite3.Error:
            return {"status": "unavailable"}

    def close(self):
        with self.lock:
            self.db.close()
