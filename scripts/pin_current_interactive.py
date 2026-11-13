"""Create a NEW current-source interactive manifest; preserve all historical pins."""
from __future__ import annotations
import argparse
from dataclasses import replace
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]


def main() -> None:
    from scripts import current_interactive_runtime as current
    from scripts import interactive_runtime as base
    from threat_hunting.evaluation import experimental_comparison as p
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "configs/interactive/dashboard_live_v3.json")
    parser.add_argument("--output", type=Path, default=ROOT / "configs/interactive/runtime_manifest_live_v2.json")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    config = p._read(args.config)
    paths = p._runtime_sources(ROOT / config["runtime_artifacts"])
    base.validate_consumers(paths)
    manifest = {"schema_version": current.SCHEMA, "purpose": "interactive_current_source", "profile_id": config["profile_id"],
        "benchmark_certified": False, "generation_preflight_certified": False,
        "config_sha256": p.sha256(args.config), "code_sha256": p._code_manifest(), "adapter_sha256": current.adapter_hashes(),
        "frontend_sha256": base.frontend_hashes(), "model": p._safe_config(replace(p.LLMConfig.from_env(), max_retries=1)),
        "artifacts": p._source_manifest(paths), "cases_sha256": p.sha256(ROOT / config["benchmark"]),
        "gate_policy_sha256": p.sha256(ROOT / config["gate_policy"]),
        "runtime_artifacts_config_sha256": p.sha256(ROOT / config["runtime_artifacts"]),
        "generation_contract": config["generation_contract"], "dependency_spec_sha256": p.sha256(ROOT / "pyproject.toml"),
        "environment": current.environment_versions(), "approval_status": "pending_human_review",
        "offline_preflight_status": "per_question_profile; offline verification recorded separately; not a benchmark pin",
        "historical_release_preserved": True, "automatic_retry": False}
    candidate = args.output.with_suffix(".candidate.json")
    p._write(candidate, manifest)
    current.verify_current_manifest(args.config, candidate)
    if args.output.exists():
        raise FileExistsError(args.output)
    candidate.rename(args.output)
    print("NEW_CURRENT_INTERACTIVE_MANIFEST_VERIFIED; 0 LLM calls")


if __name__ == "__main__":
    main()
