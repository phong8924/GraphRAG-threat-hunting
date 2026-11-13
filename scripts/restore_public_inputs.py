"""Restore only exact hash-matching public inputs; never replace an existing raw file."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
from typing import Any, BinaryIO
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_REPOSITORIES = {("OTRF", "Security-Datasets"), ("SigmaHQ", "sigma"), ("mitre-attack", "attack-stix-data")}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_target(root: Path, relative: str) -> Path:
    if PureWindowsPath(relative).drive:
        raise ValueError("Input target must be relative")
    target = (root / relative.replace("\\", "/")).resolve()
    if not target.is_relative_to(root.resolve()) or not target.is_relative_to((root / "data").resolve()):
        raise ValueError("Input target must remain under data/")
    return target


def validate_url(url: str) -> None:
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if (parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or
            parsed.username or parsed.password or parsed.query or parsed.fragment or len(parts) < 4 or
            tuple(parts[:2]) not in ALLOWED_REPOSITORIES or len(parts[2]) != 40 or
            any(c not in "0123456789abcdef" for c in parts[2])):
        raise ValueError("Require an immutable revision from an allowed upstream repository")


def stream_copy(source: BinaryIO, target: BinaryIO, limit: int) -> None:
    size = 0
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        if size > limit:
            raise ValueError("Downloaded data exceeds expected size limit")
        target.write(chunk)


def restore_one(root: Path, staging: Path, entry: dict, source: dict) -> dict[str, Any]:
    """Stage/validate bytes, then create the original filename exclusively."""
    if (Path(entry["filename"]).name != entry["filename"] or "\\" in entry["filename"] or
            source["kind"] not in {"file", "zip_member"}):
        raise ValueError("Invalid input filename or source kind")
    target = safe_target(root, entry["path"])
    if target.exists():
        if target.stat().st_size != entry["size_bytes"] or digest(target) != entry["sha256"]:
            raise ValueError("Existing input differs; preserved without replacement: " + entry["filename"])
        return {"filename": entry["filename"], "status": "already_verified", "sha256": entry["sha256"]}
    validate_url(source["url"])
    staging.mkdir(parents=True, exist_ok=True)
    archive = source["kind"] == "zip_member"
    downloaded = staging / (entry["filename"] + ".zip" if archive else entry["filename"])
    limit = entry["size_bytes"] + 1024 * 1024 if archive else entry["size_bytes"]
    request = Request(source["url"], headers={"User-Agent": "threat-hunting-input-recovery/1"})
    with urlopen(request, timeout=60) as response:
        validate_url(response.geturl())
        with downloaded.open("xb") as stream:
            stream_copy(response, stream, limit)
    candidate = downloaded
    if archive:
        if digest(downloaded) != source["archive_sha256"]:
            raise ValueError("Upstream archive hash mismatch: " + entry["filename"])
        candidate = staging / entry["filename"]
        with zipfile.ZipFile(downloaded) as zipped:
            members = [item for item in zipped.infolist() if item.filename == source["member"]]
            if len(members) != 1 or members[0].file_size != entry["size_bytes"]:
                raise ValueError("Upstream archive member mismatch")
            with zipped.open(members[0]) as stream, candidate.open("xb") as output:
                stream_copy(stream, output, entry["size_bytes"])
    if candidate.stat().st_size != entry["size_bytes"] or digest(candidate) != entry["sha256"]:
        raise ValueError("Selected input hash/size mismatch: " + entry["filename"])
    target.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite, rename or edit any existing raw input. Partial I/O failures remain visible.
    with candidate.open("rb") as stream, target.open("xb") as output:
        shutil.copyfileobj(stream, output, 1024 * 1024)
    if digest(target) != entry["sha256"]:
        raise OSError("Installed input read-back mismatch")
    return {"filename": entry["filename"], "path": entry["path"], "status": "restored_exact_match",
            "sha256": entry["sha256"], "size_bytes": entry["size_bytes"], "url": source["url"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="Explicitly download public originals; otherwise print a plan")
    parser.add_argument("--report", type=Path, help="NEW JSON report path; never overwrite")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "configs/knowledge/public_input_sources_v1.json").read_text(encoding="utf-8-sig"))
    inventory = json.loads((ROOT / manifest["expected_inventory"]).read_text(encoding="utf-8-sig"))["inputs"]
    sources = {entry["filename"]: entry for entry in manifest["sources"]}
    if len(sources) != 10 or {entry["filename"] for entry in inventory} != set(sources):
        raise ValueError("Require the ten exact selected inputs")
    for entry in sources.values():
        validate_url(entry["url"])
    if not args.download:
        print(json.dumps({"mode": "plan_only", "sources": list(sources.values()), "llm_calls": 0}, indent=2))
        return 0
    staging = ROOT / "outputs/downloads" / datetime.now(timezone.utc).strftime("public-inputs-%Y%m%dT%H%M%S%fZ")
    report: dict[str, Any] = {"schema_version": "public-input-recovery-result/v1", "status": "passed",
                              "inputs": [], "llm_calls": 0, "historical_pins_changed": False}
    for entry in inventory:
        try:
            report["inputs"].append(restore_one(ROOT, staging, entry, sources[entry["filename"]]))
            print("Verified: " + entry["filename"], flush=True)
        except Exception as exc:
            report.update(status="blocked", failed_filename=entry["filename"], error_type=type(exc).__name__)
            print("Stopped: " + entry["filename"] + "; " + type(exc).__name__, flush=True)
            break  # No retry or security-control changes after an inaccessible artifact.
    if args.report:
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
