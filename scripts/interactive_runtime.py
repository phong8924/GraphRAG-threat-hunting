"""Interactive adapter over the frozen harness; receipts are not benchmark snapshots.

Kept beside the launcher so the historical replay source closure stays intact.
The interactive manifest pins this adapter separately AND the entire shared core.
"""
from __future__ import annotations

from copy import copy, deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

from threat_hunting.evaluation import experimental_comparison as p
from threat_hunting.ground_truth import load_ground_truth_document
from threat_hunting.retrieval.context_packing import unpack_context
from threat_hunting.server.experimental import ExperimentalRequest, ExperimentalSession, response_payload

ROOT = p.ROOT
MANIFEST_SCHEMA = "interactive-runtime-manifest/v1"
RECEIPT_SCHEMA = "interactive-evidence-receipt/v1"
ADAPTER_FILES = ("scripts/interactive_runtime.py", "scripts/serve_interactive_ui.py",
                 "scripts/pin_interactive_runtime.py", "START_DASHBOARD_INTERACTIVE.cmd")
SCENARIOS = {"mshta-powershell", "purplesharp-ad", "regsvr32-c2"}


def digest(value: Any) -> str:
    return hashlib.sha256(p.canonical_bytes(value)).hexdigest()


def pointer_value(document: Any, pointer: str) -> Any:
    """Resolve an RFC6901 pointer, including array indexes, without eval."""
    if pointer and not pointer.startswith("/"):
        raise ValueError("Invalid JSON pointer")
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        document = document[int(key)] if isinstance(document, list) else document[key]
    return document


def adapter_hashes() -> dict[str, str]:
    return {name: p.sha256(ROOT / name) for name in ADAPTER_FILES}


def frontend_hashes() -> dict[str, str]:
    """Lock the current interactive source, build inputs and served build together."""
    frontend = ROOT / "frontend"
    required = ("src/App.tsx", "src/index.css", "dist/index.html", "package.json",
                "package-lock.json", "index.html", "experimental.html", "qa.html",
                "vite.config.ts", "tsconfig.json", "tailwind.config.js", "postcss.config.js")
    for name in required:
        if not (frontend / name).is_file():
            raise ValueError("Interactive frontend file missing: " + name)
    paths = {frontend / name for name in required}
    for directory in ("src", "dist"):
        paths.update(path for path in (frontend / directory).rglob("*") if path.is_file())
    return {path.relative_to(ROOT).as_posix(): p.sha256(path) for path in sorted(paths)}


def validate_consumers(paths: dict) -> None:
    """Schema plus GT/corpus/graph/index hash bindings, for all three scenarios."""
    if set(paths) != SCENARIOS:
        raise ValueError("Interactive requires the three current scenarios")
    for sid, files in paths.items():
        gt = load_ground_truth_document(files["gt_path"])
        corpus = p.load_retrieval_corpus(files["corpus_path"])
        graph = p.load_knowledge_graph(files["graph_path"])
        index = p.load_vector_index(files["index_path"])
        if gt["scenario"]["scenario_id"] != sid or corpus["scenario_id"] != sid or graph["scenario_id"] != sid:
            raise ValueError("Consumer scenario mismatch")
        for doc in (corpus, graph):
            if doc["source_ground_truth"]["sha256"] != p.sha256(files["gt_path"]):
                raise ValueError("Consumer ground truth hash mismatch")
        if index["corpus_provenance"]["sha256"] != p.sha256(files["corpus_path"]):
            raise ValueError("Index corpus hash mismatch")


def verify_manifest(config_path: Path, manifest_path: Path, *, validate_schema: bool = True) -> dict:
    """Interactive integrity never reads any benchmark preflight artifacts."""
    config, manifest = p._read(config_path), p._read(manifest_path)
    if manifest.get("schema_version") == "interactive-runtime-manifest/v2":
        from scripts.current_interactive_runtime import verify_current_manifest
        return verify_current_manifest(config_path, manifest_path, validate_schema=validate_schema)
    if (manifest.get("schema_version") != MANIFEST_SCHEMA or
            manifest.get("purpose") != "interactive_per_question" or
            manifest.get("benchmark_certified") is not False or
            manifest.get("generation_preflight_certified") is not False):
        raise ValueError("Require an explicit interactive manifest, not a benchmark pin")
    if (config.get("runtime_mode") != "interactive_per_question" or
            config.get("schema_version") != "experimental-comparison-config/v2" or
            config.get("maximum_llm_requests") != 6 or config.get("branches") != list(p.BRANCHES) or
            "final_run_policy" in config):
        raise ValueError("Invalid interactive configuration")
    if p.sha256(config_path) != manifest["config_sha256"]:
        raise ValueError("Interactive config hash mismatch")
    if adapter_hashes() != manifest["adapter_sha256"] or p._code_manifest() != manifest["code_sha256"]:
        raise ValueError("Interactive runtime source mismatch")
    if p.sha256(ROOT / "configs/release_current.json") != manifest["release_registry_sha256"]:
        raise ValueError("Current release registry mismatch")
    release = p._read(ROOT / "configs/release_current.json")
    if (p.sha256(ROOT / release["pin"]) != manifest["base_release_pin_sha256"] or
            p.sha256(ROOT / release["config"]) != manifest["base_release_config_sha256"]):
        raise ValueError("Base release changed")
    base_config, base_pin = p._read(ROOT / release["config"]), p._read(ROOT / release["pin"])
    if manifest["code_sha256"] != base_pin["code_sha256"]:
        raise ValueError("Interactive shared core differs from release")
    if frontend_hashes() != manifest["frontend_sha256"]:
        raise ValueError("Interactive frontend source/build hash mismatch")
    for field in ("runtime_artifacts", "gate_policy", "gate_contract", "generation_contract", "retrieval",
                  "graph_expansion", "maximum_context_utf8_bytes", "maximum_messages_utf8_bytes", "validator_policy_id"):
        if config[field] != base_config[field]:
            raise ValueError("Interactive shared configuration changed: " + field)
    if manifest["model"] != base_pin["model"]:
        raise ValueError("Interactive model/provider differs from release")
    paths = p._runtime_sources(ROOT / config["runtime_artifacts"])
    if p._source_manifest(paths) != manifest["artifacts"] or manifest["artifacts"] != base_pin["artifacts"]:
        raise ValueError("Interactive consumers differ from release")
    if validate_schema:
        validate_consumers(paths)
    return manifest


def evidence_references(projection: dict, paths: dict[str, Path]) -> list[dict]:
    """Point to original chunks/nodes/edges; never duplicate their telemetry."""
    lookup = {}
    for field, collection, kind, id_key in (("corpus_path", "chunks", "chunk", "chunk_id"),
            ("graph_path", "nodes", "node", "node_id"), ("graph_path", "edges", "edge", "edge_id")):
        document = p._read(paths[field])
        for i, item in enumerate(document[collection]):
            lookup[(kind, item[id_key])] = (field, f"/{collection}/{i}", item)
    references = []
    for unit in projection.get("units", []):
        origin = unit["origin"]
        field, pointer, item = lookup[(origin["kind"], origin["item_id"])]
        references.append({"origin": origin, "consumer": field, "json_pointer": pointer,
                           "object_sha256": digest(item), "source": unit["source"],
                           "source_references": unit["source_references"]})
    return references


def resolve_receipt(receipt: dict, manifest: dict) -> list[dict]:
    """Verify hashes/pointers and return the exact source objects for review.

    Receipts are an audit index, NOT serialized prompt inputs or replay fixtures.
    Gate and validator still receive the full original contracts in memory.
    """
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("benchmark_result") is not False:
        raise ValueError("Invalid interactive receipt schema")
    if receipt.get("manifest_content_sha256") != digest(manifest):
        raise ValueError("Receipt manifest hash mismatch")
    files = manifest["artifacts"][receipt["scenario_id"]]
    documents, resolved = {}, []
    for ref in receipt["evidence"]:
        entry = files[ref["consumer"]]
        path = (ROOT / entry["path"]).resolve()
        if not path.is_relative_to(ROOT) or p.sha256(path) != entry["sha256"]:
            raise ValueError("Receipt consumer hash mismatch")
        if ref["consumer"] not in documents:
            documents[ref["consumer"]] = p._read(path)
        item = pointer_value(documents[ref["consumer"]], ref["json_pointer"])
        kind, identifier = ref["origin"]["kind"], ref["origin"]["item_id"]
        if (digest(item) != ref["object_sha256"] or item[kind + "_id"] != identifier or
                item["source"] != ref["source"] or item["source_references"] != ref["source_references"]):
            raise ValueError("Receipt evidence pointer/hash mismatch")
        resolved.append(deepcopy(item))
    return resolved


class InteractiveSession(ExperimentalSession):
    """Use the existing UI/protocol, shared pipeline and explicit per-session cap6."""

    def __init__(self, output: Path, *, config_path: Path, pin_path: Path, **kwargs: Any) -> None:
        manifest = verify_manifest(config_path, pin_path)
        if kwargs.get("live") and not 1 <= kwargs.get("max_requests", 0) <= 6:
            raise ValueError("Interactive Live cap must be in 1..6")
        self.reservations = 0
        super().__init__(output, config_path=config_path, pin_path=pin_path, **kwargs)
        self.interactive_manifest = manifest

    def metadata(self) -> dict:
        return {**super().metadata(), "runtime_mode": "interactive_per_question",
                "offline_preflight_status": "not_required_for_interactive_not_benchmark_certified",
                "benchmark_certified": False, "generation_preflight_certified": False,
                "reserved_request_slots": self.reservations,
                "release_limitation": "Interactive từng câu · chưa chứng nhận benchmark hoặc chất lượng generation. Saved replay dùng checkpoint riêng; không phải kết quả câu hỏi mới.",
                "artifact_profiles": [{"id": self.config["profile_id"], "label": "Interactive RAG / GraphRAG · CTI · draft"},
                                      {"id": "historical-replay", "label": "Checkpoint 15×2 · saved replay only"}]}

    def saved(self, case_id: str, branch: str) -> dict:
        # Retain hash-closed v20 replay without implying an interactive benchmark.
        release = p._read(ROOT / "configs/release_current.json")
        replay = copy(self)
        replay.config_path, replay.pin_path = ROOT / release["config"], ROOT / release["pin"]
        replay.config, replay.pin = p._read(replay.config_path), p._read(replay.pin_path)
        response = ExperimentalSession.saved(replay, case_id, branch)
        # Keep the interactive controls; provenance/revalidation identify historical results.
        response["configuration"] = self.metadata()
        return response

    def run(self, request: ExperimentalRequest) -> dict:
        with self.lock:
            artifacts: dict[str, Any] = {}
            row = {"branch": request.branch, "scenario_id": request.scenario_id, "outcome": "runtime_error",
                   "llm_http_attempts": 0, "fallback_used": False, "human_review_required": True}
            directory = self.output / uuid4().hex
            persisted = False

            def emit(name: str, value: Any) -> None:
                artifacts[name] = deepcopy(value)

            def receipt() -> dict:
                return {"schema_version": RECEIPT_SCHEMA, "benchmark_result": False,
                        "created_utc": datetime.now(timezone.utc).isoformat(),
                        "scenario_id": request.scenario_id, "branch": request.branch,
                        "query_sha256": digest(request.query), "manifest_sha256": p.sha256(self.pin_path),
                        "manifest_content_sha256": digest(self.pin),
                        "artifact_sha256": {k: digest(v) for k, v in artifacts.items()},
                        "evidence": evidence_references(artifacts.get("evidence_contract", {}), self.paths[request.scenario_id]),
                        "decisions": {k: {f: v[f] for f in ("decision", "reason_codes", "abstention_stage", "budget_exceeded") if f in v}
                                      for k in ("scope", "gate", "eligibility") if (v := artifacts.get(k))},
                        "result": {k: row[k] for k in ("outcome", "computed_outcome", "validation_status", "llm_http_attempts", "context_sha256", "messages_sha256", "abstention_stage", "persistence_error", "error_type") if k in row},
                        "provider_error": {k: v for k, v in row.get("provider_error", {}).items() if k in {"kind", "http_status", "automatic_retry", "retry_after_seconds"}},
                        "stopped_reason": self.stopped,
                        "validation_sha256": digest(artifacts.get("validation", artifacts.get("validation_failure"))),
                        "llm_http_attempts_session": self.attempts, "reserved_request_slots": self.reservations}

            def save(name: str) -> None:
                nonlocal persisted
                value = receipt()
                p._write(directory / (name + ".json"), value)
                saved = p._read(directory / (name + ".json"))
                if saved != value:
                    raise OSError("Interactive receipt read-back mismatch")
                resolve_receipt(saved, self.pin)
                persisted = True

            try:
                directory.mkdir()
                verify_manifest(self.config_path, self.pin_path, validate_schema=False)
                paths = self.paths[request.scenario_id]
                corpus = p.load_retrieval_corpus(paths["corpus_path"])
                scope = p.assess_query_scope(request.query, corpus=corpus, graph={})
                emit("scope", scope)
                if scope["decision"] == "abstain":
                    row.update(outcome="abstain", gate_decision="abstain", eligibility_decision="abstain", abstention_stage="query_scope")
                else:
                    index = p.load_vector_index(paths["index_path"])
                    if self.backend is None:
                        embedding = index["embedding"]
                        self.backend = p.SentenceTransformerEmbeddingBackend(model_id=embedding["model_id"],
                            model_revision=embedding["model_revision"], dimension=embedding["dimension"],
                            device="cpu", batch_size=32, show_progress_bar=False)
                        self.backend.load()
                    prepared = p.prepare_branch(request.query, request.branch, paths, corpus, index,
                                                self.backend, self.config, self.policy, emit)
                    row.update(prepared["row"])
                    if prepared["budget_exceeded"]:
                        row.update(outcome="abstain", eligibility_decision="abstain", abstention_stage="context_budget", budget_exceeded=True)
                    elif prepared["gate"]["decision"] == "abstain":
                        row["outcome"] = "abstain"
                    elif not self.live:
                        row["outcome"] = "dry_run_no_generation"
                    elif self.stopped:
                        row["outcome"] = "not_run_after_stop"
                    elif self.reservations >= self.max_requests:
                        row["outcome"] = "not_run_request_limit"
                    else:
                        # Durable reservation precedes client construction. A crash consumes
                        # a slot conservatively; sessions never resume/reset existing output.
                        self.reservations += 1
                        row["outcome"] = "reserved_before_generation"
                        try:
                            save("reservation")
                        except (OSError, ValueError) as exc:
                            raise PersistenceError("reservation", exc) from exc
                        generated, self.stopped = p.generate_branch(prepared["messages"], prepared["context"],
                            self.llm_config, self.client_factory, emit)
                        row.update(generated)
                        self.attempts += row["llm_http_attempts"]
                if p._source_manifest(self.paths) != self.sources:
                    raise ValueError("Interactive consumers changed during request")
            except PersistenceError as exc:
                row.update(outcome="persistence_error", persistence_error=exc.details)
                self.stopped = "persistence_error"
            except OSError as exc:
                row.update(outcome="persistence_error", persistence_error=io_details("runtime_io", exc))
                self.stopped = "persistence_error"
            except Exception as exc:
                row.update(outcome="runtime_error", error_type=type(exc).__name__)
            computed = row["outcome"]
            try:
                save("result_receipt")
            except (OSError, ValueError) as exc:
                row.update(outcome="persistence_error", computed_outcome=computed,
                           persistence_error=io_details("result_receipt", exc))
                self.stopped, persisted = "persistence_error", False
            response = response_payload(request, row, artifacts, self.metadata(),
                {"mode": "interactive_per_question", "directory": directory.relative_to(ROOT).as_posix(),
                 "benchmark_result": False, "persistence_status": "saved" if persisted and computed != "persistence_error" else "failed",
                 "receipt_schema": RECEIPT_SCHEMA, "full_evidence_contract": "memory_only"})
            if row["outcome"] == "persistence_error":
                response["report"] = None
                response["diagnostic"] = artifacts.get("validation", artifacts.get("validation_failure"))
            if self.pin.get("schema_version") == "interactive-runtime-manifest/v2":
                text = artifacts.get("raw_model_output", {}).get("text")
                response["generation_evidence"] = {
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "model_output_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None,
                    "new_llm_response": bool(row.get("llm_http_attempts") and isinstance(text, str)),
                    "benchmark_result": False,
                }
            return response


def io_details(stage: str, exc: Exception) -> dict:
    return {"stage": stage, "error_type": type(exc).__name__, "errno": getattr(exc, "errno", None),
            "winerror": getattr(exc, "winerror", None)}


class PersistenceError(Exception):
    def __init__(self, stage: str, cause: Exception) -> None:
        super().__init__(stage)
        self.details = io_details(stage, cause)


def create_interactive_app(session: InteractiveSession):
    """Keep the existing UI; its HTTP error reader displays persistence_error on507."""
    from fastapi.responses import JSONResponse
    from threat_hunting.server.experimental import create_app

    class Transport:
        def __getattr__(self, name: str) -> Any:
            return getattr(session, name)

        def run(self, request: ExperimentalRequest) -> Any:
            response = session.run(request)
            if response["outcome"] == "persistence_error":
                return JSONResponse(status_code=507, content={**response,
                    "detail": "persistence_error: artifact chưa được lưu/xác minh đầy đủ; session đã dừng. Xem result.persistence_error và diagnostic."})
            return response

    return create_app(Transport())
