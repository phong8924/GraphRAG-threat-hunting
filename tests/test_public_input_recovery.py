"""Network-free recovery tests: dummy bytes never replace a selected original."""
import hashlib
import io
from pathlib import Path
import zipfile

import pytest

from scripts import restore_public_inputs as recovery

URL = "https://raw.githubusercontent.com/OTRF/Security-Datasets/" + "a" * 40 + "/fixture.zip"


def entry(data=b"SYNTHETIC INPUT\n"):
    return {"filename": "fixture.json", "path": "data/raw/fixture.json", "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def test_existing_original_is_verified_without_network_and_never_replaced(tmp_path, monkeypatch):
    target = tmp_path / "data/raw/fixture.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"SYNTHETIC INPUT\n")
    monkeypatch.setattr(recovery, "urlopen", lambda *a, **k: pytest.fail("Existing original must not trigger network"))
    assert recovery.restore_one(tmp_path, tmp_path / "staging", entry(), {"kind": "file", "url": URL})["status"] == "already_verified"
    target.write_bytes(b"USER'S DIFFERENT ORIGINAL")
    with pytest.raises(ValueError, match="preserved"):
        recovery.restore_one(tmp_path, tmp_path / "staging", entry(), {"kind": "file", "url": URL})
    assert target.read_bytes() == b"USER'S DIFFERENT ORIGINAL"


@pytest.mark.parametrize("url", ["http://raw.githubusercontent.com/OTRF/Security-Datasets/master/file", "https://example.com/file",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/file", URL + "?token=private"])
def test_unpinned_or_untrusted_download_urls_are_rejected(url):
    with pytest.raises(ValueError):
        recovery.validate_url(url)


@pytest.mark.parametrize("zip_member", [False, True])
def test_downloaded_bytes_are_verified_before_installation(tmp_path, monkeypatch, zip_member):
    raw = b"SYNTHETIC INPUT\n"
    data = raw
    source = {"kind": "file", "url": URL}
    if zip_member:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zipped:
            zipped.writestr("fixture.json", raw)
            zipped.writestr("../outside.json", b"MUST NOT BE EXTRACTED")
        data = buffer.getvalue()
        source.update(kind="zip_member", member="fixture.json", archive_sha256=hashlib.sha256(data).hexdigest())
    class Download(io.BytesIO):
        def geturl(self): return URL
    monkeypatch.setattr(recovery, "urlopen", lambda *a, **k: Download(data))
    result = recovery.restore_one(tmp_path, tmp_path / "staging", entry(), source)
    assert result["status"] == "restored_exact_match"
    assert (tmp_path / "data/raw/fixture.json").read_bytes() == raw
    assert not (tmp_path / "outside.json").exists()


def test_bad_hash_never_publishes_selected_filename(tmp_path, monkeypatch):
    class Download(io.BytesIO):
        def geturl(self): return URL
    monkeypatch.setattr(recovery, "urlopen", lambda *a, **k: Download(b"DIFFERENT BYTES!"))
    with pytest.raises(ValueError, match="hash/size"):
        recovery.restore_one(tmp_path, tmp_path / "staging", entry(), {"kind": "file", "url": URL})
    assert not (tmp_path / "data/raw/fixture.json").exists()


def test_targets_outside_data_and_unsafe_staging_names_are_rejected(tmp_path):
    with pytest.raises(ValueError): recovery.safe_target(tmp_path, "../outside.json")
    with pytest.raises(ValueError): recovery.safe_target(tmp_path, ".env")
    invalid = {**entry(), "filename": "../fixture.json"}
    with pytest.raises(ValueError):
        recovery.restore_one(tmp_path, tmp_path / "staging", invalid, {"kind": "file", "url": URL})
