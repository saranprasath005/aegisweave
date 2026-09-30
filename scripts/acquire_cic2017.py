"""Acquire the authors' corrected CICIDS2017 CSV archive without executing content."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import zipfile

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aegisweave.corpus import file_sha256

SOURCE = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
DOCS = "https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html"
TARGET = ROOT / "var/datasets/cicids2017-improved"


def main():
    TARGET.mkdir(parents=True, exist_ok=True)
    archive = TARGET / "CICIDS2017_improved.zip"
    if not archive.exists():
        partial = archive.with_suffix(".zip.partial")
        total, last = 0, 0
        with httpx.Client(follow_redirects=True, timeout=120) as client, client.stream("GET", SOURCE) as response:
            response.raise_for_status()
            with partial.open("wb") as out:
                for block in response.iter_bytes(1024 * 1024):
                    total += len(block)
                    if total > 512 * 1024 * 1024:
                        raise ValueError("Archive exceeds expected size bound")
                    out.write(block)
                    if total - last >= 32 * 1024 * 1024:
                        print(f"Downloaded {total // (1024 * 1024)} MiB", flush=True)
                        last = total
        if not zipfile.is_zipfile(partial):
            raise ValueError("Download was not a ZIP archive")
        partial.rename(archive)
    raw = TARGET / "raw"
    raw.mkdir(exist_ok=True)
    files = {}
    with zipfile.ZipFile(archive) as bundle:
        members = [m for m in bundle.infolist() if m.filename.lower().endswith(".csv") and not m.is_dir()]
        names = [PurePosixPath(m.filename).name for m in members]
        if not members or len(names) != len(set(names)) or sum(m.file_size for m in members) > 4 * 1024**3:
            raise ValueError("Unexpected CSV members or expanded archive size")
        for member, name in zip(members, names):
            if "\\" in name or ":" in name or name in {".", ".."}:
                raise ValueError("Unsafe archive member name")
            target = raw / name
            digest = hashlib.sha256()
            if target.exists():
                with bundle.open(member) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                if file_sha256(target) != digest.hexdigest():
                    raise ValueError(f"Existing capture differs from archive: {name}")
            else:
                partial = target.with_suffix(".csv.partial")
                with bundle.open(member) as source, partial.open("wb") as out:
                    shutil.copyfileobj(source, out)
                partial.rename(target)
            files[name] = {"bytes": target.stat().st_size, "sha256": file_sha256(target)}
            print(f"Verified {name}: {target.stat().st_size} bytes", flush=True)
    manifest = {"dataset": "CICIDS2017 improved (Liu et al., CNS 2022)", "source": SOURCE,
                "documentation": DOCS, "archive_sha256": file_sha256(archive), "files": files,
                "authenticity": "Downloaded over HTTPS from the correction authors; locally hashed, no published checksum verified",
                "training_started": False}
    (TARGET / "acquisition.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
