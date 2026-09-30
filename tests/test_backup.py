import sqlite3

import pytest

from aegisweave.backup import restore, snapshot


def test_online_wal_snapshot_and_verified_restore(tmp_path):
    source = tmp_path / "source.db"
    db = sqlite3.connect(source)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA user_version=2")
        db.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO evidence VALUES (1,'committed')")
        db.commit()
        manifest = snapshot(source, tmp_path / "backup")
        assert manifest["schema_version"] == 2
        db.execute("INSERT INTO evidence VALUES (2,'after snapshot')")
        db.commit()
        restore(tmp_path / "backup", tmp_path / "restored.db")
        with sqlite3.connect(tmp_path / "restored.db") as restored:
            assert restored.execute("SELECT * FROM evidence").fetchall() == [(1, "committed")]
        with pytest.raises(FileExistsError):
            restore(tmp_path / "backup", source)
        assert db.execute("SELECT count(*) FROM evidence").fetchone()[0] == 2
        with pytest.raises(FileExistsError):
            snapshot(source, tmp_path / "backup")
    finally:
        db.close()


def test_corrupt_or_partial_backup_is_not_restored(tmp_path):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE evidence (id INTEGER)")
    snapshot(source, tmp_path / "backup")
    (tmp_path / "backup" / "database.sqlite").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checksum"):
        restore(tmp_path / "backup", tmp_path / "restored.db")
    assert not (tmp_path / "restored.db").exists()
    with pytest.raises(ValueError, match="does not exist"):
        snapshot(tmp_path / "missing.db", tmp_path / "new-backup")
