"""Current-source interactive profile; independently pinned, never edits replay history."""
from __future__ import annotations

from copy import deepcopy
from importlib import metadata
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from scripts import interactive_runtime as base
from threat_hunting.evaluation import experimental_comparison as p
from threat_hunting.server.experimental import ExperimentalRequest

ROOT = p.ROOT
SCHEMA = "interactive-runtime-manifest/v2"
ADAPTERS = (*base.ADAPTER_FILES, "scripts/current_interactive_runtime.py",
            "scripts/pin_current_interactive.py", "scripts/serve_current_interactive_ui.py", "scripts/build_current_live_consumers.py", "START_DASHBOARD_LIVE.cmd")
PACKAGES = ("PyYAML", "sentence-transformers", "python-dotenv", "fastapi", "uvicorn", "pydantic", "httpx",
            "numpy", "torch", "transformers", "huggingface-hub", "scikit-learn", "scipy")


def environment_versions() -> dict[str, str]:
    return {name: metadata.version(name) for name in PACKAGES}


def adapter_hashes() -> dict[str, str]:
    return {name: p.sha256(ROOT / name) for name in ADAPTERS}


def verify_current_manifest(config_path: Path, manifest_path: Path, *, validate_schema: bool = True) -> dict:
    """Every binding belongs to this new profile, not an amended historical pin."""
    config, manifest = p._read(config_path), p._read(manifest_path)
    if (manifest.get("schema_version") != SCHEMA or manifest.get("purpose") != "interactive_current_source"
            or manifest.get("benchmark_certified") is not False or manifest.get("generation_preflight_certified") is not False):
        raise ValueError("Require a current-source interactive manifest; no benchmark certification")
    if (config.get("runtime_mode") != "interactive_per_question" or config.get("schema_version") != "experimental-comparison-config/v2"
            or config.get("branches") != list(p.BRANCHES) or type(config.get("maximum_llm_requests")) is not int
            or not 1 <= config["maximum_llm_requests"] <= 6
            or config.get("gate_contract") != "source-evidence-contract/v2" or config.get("generation_contract") != "source-meaning/v3"
            or "final_run_policy" in config or config.get("profile_id") != manifest.get("profile_id")):
        raise ValueError("Invalid current interactive configuration")
    if p.sha256(config_path) != manifest["config_sha256"]:
        raise ValueError("Current interactive config hash mismatch")
    if p._code_manifest() != manifest["code_sha256"] or adapter_hashes() != manifest["adapter_sha256"]:
        raise ValueError("Current interactive source inventory/hash mismatch")
    if base.frontend_hashes() != manifest["frontend_sha256"]:
        raise ValueError("Current interactive frontend source/build inventory/hash mismatch")
    for field, key in (("benchmark", "cases_sha256"), ("gate_policy", "gate_policy_sha256"),
                       ("runtime_artifacts", "runtime_artifacts_config_sha256")):
        if p.sha256(ROOT / config[field]) != manifest[key]:
            raise ValueError("Current interactive binding mismatch: " + field)
    if p.sha256(ROOT / "pyproject.toml") != manifest["dependency_spec_sha256"] or environment_versions() != manifest["environment"]:
        raise ValueError("Current interactive dependency environment changed")
    paths = p._runtime_sources(ROOT / config["runtime_artifacts"])
    if p._source_manifest(paths) != manifest["artifacts"]:
        raise ValueError("Current interactive consumers changed")
    if validate_schema:
        base.validate_consumers(paths)
    from dataclasses import replace
    if p._safe_config(replace(p.LLMConfig.from_env(), max_retries=1)) != manifest["model"]:
        raise ValueError("Current interactive model/provider/settings/validator binding changed")
    if manifest.get("generation_contract") != config["generation_contract"]:
        raise ValueError("Current interactive generation contract mismatch")
    return manifest


class CurrentInteractiveSession(base.InteractiveSession):
    """Same E5/RRF/gate/prompt/client/validator and receipt reservation path as the harness."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.recent_results: list[dict] = []
        super().__init__(*args, **kwargs)

    def metadata(self) -> dict:
        value = super().metadata()
        value.update(runtime_mode="interactive_per_question", current_source_profile=True,
            saved_replay_available=False, legacy_available=False, cti_available=True,
            load_latest_on_open=True, recent_results_count=len(self.recent_results),
            artifact_profiles=[{"id": self.config["profile_id"], "label": "Giao diện hiện tại · E5 + CTI · RAG / GraphRAG + LLM"}],
            release_limitation=f"Câu hỏi mới qua pipeline E5/CTI/source gate. Draft cần người duyệt; tối đa {self.config['maximum_llm_requests']} request/phiên, không retry/fallback. Không phải benchmark.")
        return value

    def saved(self, case_id: str, branch: str) -> dict:
        raise HTTPException(409, "Current profile does not replay historical answers")

    def run(self, request: ExperimentalRequest) -> dict:
        response = super().run(request)
        self.recent_results.append(deepcopy(response))
        response["configuration"] = self.metadata()
        return response


def create_current_app(session: CurrentInteractiveSession):
    """Mount current UI, fresh generation route and read-only current-session result lookup."""
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    app = FastAPI(title="Current RAG/GraphRAG LLM dashboard", docs_url=None, redoc_url=None)

    def profile_check(profile: str | None) -> None:
        if profile not in {None, session.config["profile_id"]}:
            raise HTTPException(422, "Unknown current artifact profile")

    @app.get("/experimental-api/config")
    def config(profile: str | None = None):
        profile_check(profile)
        return {**session.metadata(), "presets": session.presets(), "fixture_ids": []}

    @app.post("/experimental-api/hunt")
    def hunt(request: ExperimentalRequest, profile: str | None = None):
        profile_check(profile)
        result = session.run(request)
        if result["outcome"] == "persistence_error":
            return JSONResponse(status_code=507, content={**result, "detail": "Persistence failed; session stopped"})
        return result

    @app.get("/experimental-api/recent")
    def recent(branch: str | None = None, profile: str | None = None):
        profile_check(profile)
        with session.lock:
            result = next((r for r in reversed(session.recent_results) if branch is None or r["request"]["branch"] == branch), None)
            if result is None:
                return None
            result = deepcopy(result)
            result["configuration"] = session.metadata()
            result["provenance"]["display_source"] = "current_session_result; read_only; zero_new_calls"
            return result

    @app.get("/experimental-api/saved")
    def saved():
        raise HTTPException(409, "No historical saved replay in this current-source profile")

    app.mount("/", StaticFiles(directory=ROOT / "frontend/dist", html=True), name="current-frontend")
    return app
