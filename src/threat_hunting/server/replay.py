"""Hash-closed replay of historical generation, independent of the serving runtime."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class ReplayArtifactError(ValueError):
    """A configured replay source is missing, incomplete or no longer authentic."""


def read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_path(root: Path, relative: str, expected: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file() or digest(path) != expected:
        raise ReplayArtifactError(f"Replay source missing or hash mismatch: {relative}")
    return path


def load_replay_index(root: Path, config_path: Path, config: dict, pin: dict) -> dict:
    """Validate the complete source closure; never silently substitute a dry-run."""
    relative = config.get("saved_results_manifest")
    if not relative:
        raise ReplayArtifactError("This profile has no configured saved replay manifest")
    manifest = root / relative
    if not manifest.is_file():
        raise ReplayArtifactError(f"Configured replay manifest is missing: {relative}")
    if not pin.get("saved_results_manifest_sha256"):
        raise ReplayArtifactError("Replay manifest is not hash-pinned by this runtime release")
    checked_path(root, relative, pin["saved_results_manifest_sha256"])
    index = read(manifest)
    if index.get("schema_version") != "historical-replay-index/v2" or index.get("runtime_config_sha256") != digest(config_path):
        raise ReplayArtifactError("Replay index schema/runtime configuration mismatch")
    source = index["source_generation"]
    docs = {}
    for name in ("config", "pin", "manifest", "results"):
        docs[name] = read(checked_path(root, source[name + "_path"], source[name + "_sha256"]))
    if (docs["pin"]["config_sha256"] != source["config_sha256"]
            or docs["config"]["profile_id"] != source["profile_id"]
            or docs["manifest"]["config_sha256"] != source["config_sha256"]
            or docs["manifest"]["runtime_pin_sha256"] != source["pin_sha256"]
            or docs["manifest"]["model"] != docs["pin"]["model"]
            or docs["results"]["mode"] != "live"):
        raise ReplayArtifactError("Historical generation provenance mismatch")
    source_rows = docs["results"]["rows"]
    cases = {c["case_id"]: c for c in read(root / config["benchmark"])["cases"]}
    expected = {case_id + ":" + b for case_id in cases for b in config["branches"]}
    rows = {r["case_id"] + ":" + r["branch"]: r for r in source_rows}
    if len(rows) != len(source_rows) or set(rows) != expected or set(index["branches"]) != expected:
        raise ReplayArtifactError("Replay must cover every distinct release case/branch")
    for key, entry in index["branches"].items():
        directory = (root / entry["directory"]).resolve()
        if not directory.is_relative_to((root / "outputs").resolve()):
            raise ReplayArtifactError("Replay directory escapes outputs")
        required = {"result.json", "context.json", "messages.json", "gate.json", "scope.json", "eligibility.json"}
        if rows[key]["llm_http_attempts"]:
            required |= {"raw_report_before_sanitize.json", "raw_model_output.json", "validation.json"}
        files = entry["files_sha256"]
        if not required <= set(files):
            raise ReplayArtifactError("Replay index omits required historical artifacts: " + key)
        for filename, expected_hash in files.items():
            path = directory / filename
            if path.resolve().parent != directory or not path.is_file() or digest(path) != expected_hash:
                raise ReplayArtifactError("Historical replay artifact hash mismatch: " + key + "/" + filename)
        if read(directory / "result.json") != rows[key]:
            raise ReplayArtifactError("Historical row differs from source results: " + key)
        request = cases[rows[key]["case_id"]]
        if (rows[key].get("scenario_id") != request["scenario_id"]
                or read(directory / "context.json")["query"]["text"] != request["request"]["query"]):
            raise ReplayArtifactError("Historical question/scenario differs from release preset: " + key)
        for name in ("context", "messages"):
            value = read(directory / (name + ".json"))
            if name == "messages":
                value = value["messages"]
            encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if hashlib.sha256(encoded).hexdigest() != rows[key][name + "_sha256"]:
                raise ReplayArtifactError("Historical model input hash mismatch: " + key)
    return index


def replay_response_data(root: Path, index: dict, key: str) -> tuple[dict, dict, dict]:
    directory = root / index["branches"][key]["directory"]
    names = ("scope", "context", "messages", "gate", "eligibility", "evidence_contract", "validation", "validation_failure")
    artifacts = {name: read(directory / (name + ".json")) for name in names if (directory / (name + ".json")).is_file()}
    source = index["source_generation"]
    pin = read(root / source["pin_path"])
    row = read(directory / "result.json")
    provenance = {"mode": "saved_experimental_replay", "source_directory": index["branches"][key]["directory"],
                  "source_result_sha256": index["branches"][key]["files_sha256"]["result.json"],
                  "source_generation_profile": source["profile_id"], "source_generation_pin_sha256": source["pin_sha256"],
                  "source_generation_config_sha256": source["config_sha256"], "source_generation_model": pin["model"],
                  "source_generation_artifacts": pin["artifacts"], "source_generation_contract": pin.get("generation_contract"),
                  "historical_validator_policy": pin["model"]["validator_policy"],
                  "historical_validation_preserved": True, "llm_requests_this_replay": 0,
                  "historical_llm_http_attempts": row["llm_http_attempts"], "benchmark_result": False}
    return row, artifacts, provenance
