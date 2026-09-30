"""SQLite online snapshots with verified restore to a new database path."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def snapshot(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if not source.is_file():
        raise ValueError("Source database does not exist")
    output.mkdir(parents=True, exist_ok=False)
    destination = output / "database.sqlite"
    original = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    copied = sqlite3.connect(destination)
    try:
        original.backup(copied, pages=256)
        integrity = copied.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            raise ValueError("Snapshot integrity check failed")
        schema_version = copied.execute("PRAGMA user_version").fetchone()[0]
    finally:
        copied.close()
        original.close()
    manifest = {"format": "aegisweave.sqlite-snapshot.v1", "created_at": datetime.now(timezone.utc).isoformat(),
                "source_name": source.name, "sha256": digest(destination), "schema_version": schema_version,
                "integrity_check": "ok"}
    # Manifest publication marks the snapshot complete. Partial folders are never restorable.
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def restore(backup, output):
    backup, output = Path(backup).resolve(), Path(output).resolve()
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    source = backup / "database.sqlite"
    if manifest.get("format") != "aegisweave.sqlite-snapshot.v1" or manifest.get("sha256") != digest(source):
        raise ValueError("Snapshot manifest or checksum mismatch")
    # Restore only to an unused path. Live replacement requires a separate maintenance step.
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb"):
        pass
    original = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    copied = sqlite3.connect(output)
    try:
        original.backup(copied, pages=256)
        if copied.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("Restored database integrity check failed")
        if copied.execute("PRAGMA user_version").fetchone()[0] != manifest["schema_version"]:
            raise ValueError("Restored schema differs from manifest")
    finally:
        copied.close()
        original.close()
    return {"restored": str(output), "schema_version": manifest["schema_version"]}
