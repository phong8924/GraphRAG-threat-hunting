"""Freeze current release integrity for per-question use, NOT benchmark certification."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from scripts.interactive_runtime import MANIFEST_SCHEMA, adapter_hashes, frontend_hashes, validate_consumers
from threat_hunting.evaluation import experimental_comparison as p


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/interactive/dashboard_v1.json")
    parser.add_argument("--output", type=Path, default=ROOT / "configs/interactive/runtime_manifest_v3.json")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    config = p._read(args.config)
    release = p._read(ROOT / "configs/release_current.json")
    base = p._read(ROOT / release["pin"])
    paths = p._runtime_sources(ROOT / config["runtime_artifacts"])
    validate_consumers(paths)
    if p._safe_config(p.LLMConfig.from_env()) != base["model"]:
        raise ValueError("Effective model/provider/validator differs from current release")
    manifest = {"schema_version": MANIFEST_SCHEMA, "purpose": "interactive_per_question",
        "benchmark_certified": False, "generation_preflight_certified": False,
        "profile_id": config["profile_id"], "config_sha256": p.sha256(args.config),
        "code_sha256": p._code_manifest(), "adapter_sha256": adapter_hashes(),
        "model": base["model"], "frontend_sha256": frontend_hashes(),
        "artifacts": p._source_manifest(paths), "cases_sha256": p.sha256(ROOT / config["benchmark"]),
        "gate_policy_sha256": p.sha256(ROOT / config["gate_policy"]),
        "runtime_artifacts_config_sha256": p.sha256(ROOT / config["runtime_artifacts"]),
        "generation_contract": config["generation_contract"],
        "release_registry_sha256": p.sha256(ROOT / "configs/release_current.json"),
        "base_release_pin_sha256": p.sha256(ROOT / release["pin"]),
        "base_release_config_sha256": p.sha256(ROOT / release["config"]),
        "verification_scope": "Schema/hash/source/config/current consumers only. No preflight completeness or generation quality certified.",
        "approval_status": "pending_human_review"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Validate before publishing, using an exclusive temporary file; never rewrite a manifest.
    from scripts.interactive_runtime import verify_manifest
    temporary = args.output.with_suffix(".candidate.json")
    with temporary.open("x", encoding="utf-8") as stream:
        import json
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    verify_manifest(args.config, temporary)
    if args.output.exists():
        raise FileExistsError(args.output)
    temporary.rename(args.output)
    print(f"Interactive manifest: {args.output}; benchmark_certified=false; LLM calls=0")


if __name__ == "__main__":
    main()
