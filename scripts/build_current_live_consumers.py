"""Version MSHTA observation bindings from verified raw/canonical data; preserve CTI/labels/history."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]


def bind_mshta_observations(document: dict, rows: list[dict]) -> dict:
    from threat_hunting.evidence.integrated import source_observation
    result = deepcopy(document)
    lookup = {(row["source_file"], row["raw_record_ref"]): row for row in rows}
    bound = 0
    for fact in result["facts"]:
        if fact["status"] != "observed":
            continue
        references = fact["source_references"]
        if not references:
            continue
        observations = []
        for reference in references:
            key = reference["source_file"], reference["raw_record_ref"]
            if key not in lookup:
                raise ValueError("MSHTA fact reference does not resolve to aligned raw/canonical observation")
            row = lookup[key]
            fields = row["canonical_fields"]
            if str(fields.get("event_id")) not in {"1", "4688"} or not fields.get("process_name") or not fields.get("parent_process_name"):
                raise ValueError("MSHTA process fact requires an actual parent/child creation record")
            observations.append(source_observation(row))
        fact["attributes"]["source_observations"] = observations
        bound += 1
    if bound != 2:
        raise ValueError("Require exactly the two reviewed MSHTA process-creation fact groups")
    return result


def main() -> None:
    for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "HF_HUB_DISABLE_IMPLICIT_TOKEN"):
        os.environ[name] = "1"
    from threat_hunting.evaluation import experimental_comparison as p
    from scripts.interactive_runtime import validate_consumers
    from threat_hunting.evidence.process_network import read_aligned
    from threat_hunting.evidence.integrated import enrich_consumers
    from threat_hunting.ground_truth.schema import validate_ground_truth_document
    from threat_hunting.retrieval import build_retrieval_corpus, build_vector_index
    from threat_hunting.graph import build_knowledge_graph

    output = ROOT / "outputs/integrated/20261112_live_v1/consumers/mshta-powershell"
    if output.exists():
        raise FileExistsError(output)
    registry = p._read(ROOT / "configs/runtime_artifacts_live_v1.json")
    paths = p._runtime_sources(ROOT / "configs/runtime_artifacts_live_v1.json")
    previous = p._read(paths["mshta-powershell"]["gt_path"])
    inventory = p._read(ROOT / "packaging/inputs.json")["inputs"]
    name = "cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json"
    raw = next(item for item in inventory if item["filename"] == name)
    canonical_dir = ROOT / "outputs/rebuild/20261112_v1/canonical"
    normalized = next(item for item in p._read(canonical_dir / "manifest.json")["files"] if item["source_filename"] == name)
    canonical = canonical_dir / normalized["canonical_events"]
    rows, stats = read_aligned(ROOT / raw["path"], canonical, raw["sha256"], normalized["canonical_events_sha256"])
    document = bind_mshta_observations(previous, rows)
    for collection in ("entities", "relationships", "evidence", "sigma_findings", "mitre_assessments", "review", "summary"):
        if document[collection] != previous[collection]:
            raise ValueError("Representation binding must preserve existing source statuses, CTI and scope")
    document["input_provenance"].extend([
        {"input_id": "current-mshta-canonical", "input_type": "canonical_events", "path": canonical.relative_to(ROOT).as_posix(),
         "sha256": p.sha256(canonical), "schema_version": "canonical-event/v2", "scenario_id": "mshta-powershell"},
        {"input_id": "current-mshta-previous-gt", "input_type": "previous_ground_truth", "path": paths["mshta-powershell"]["gt_path"].relative_to(ROOT).as_posix(),
         "sha256": p.sha256(paths["mshta-powershell"]["gt_path"]), "schema_version": previous["schema_version"], "scenario_id": "mshta-powershell"},
    ])
    validate_ground_truth_document(document)
    output.mkdir(parents=True, exist_ok=False)
    gt = output / "scenario_ground_truth.json"
    p._write(gt, document)
    corpus = build_retrieval_corpus(document, source_ground_truth_path=gt.relative_to(ROOT).as_posix(), source_ground_truth_sha256=p.sha256(gt))
    graph = build_knowledge_graph(document, ground_truth_path=gt.relative_to(ROOT).as_posix(), ground_truth_sha256=p.sha256(gt))
    enrich_consumers(document, corpus, graph)
    corpus_path, graph_path = output / "retrieval_corpus.json", output / "knowledge_graph.json"
    p._write(corpus_path, corpus); p._write(graph_path, graph)
    descriptor = p._read(paths["mshta-powershell"]["index_path"])["embedding"]
    backend = p.SentenceTransformerEmbeddingBackend(model_id=descriptor["model_id"], model_revision=descriptor["model_revision"],
        dimension=descriptor["dimension"], device="cpu", batch_size=32, show_progress_bar=False)
    backend.load()
    index = build_vector_index(corpus, corpus_path=corpus_path.relative_to(ROOT).as_posix(), corpus_sha256=p.sha256(corpus_path),
        embedding=descriptor, embed_documents=backend.embed_documents)
    index_path = output / "vector_index_e5.json"
    p._write(index_path, index)
    registry["profile_id"] = "current-interactive-consumers-20261112-v2"
    registry["interpretation"] = "MSHTA structured raw/canonical observation bindings corrected in a NEW consumer; CTI, evidence groups, labels and review unchanged. Auth/network consumers exact reuse."
    registry["scenarios"]["mshta-powershell"] = {"paths": {key: (output / filename).relative_to(ROOT).as_posix() for key, filename in (
        ("gt_path", "scenario_ground_truth.json"), ("corpus_path", "retrieval_corpus.json"), ("graph_path", "knowledge_graph.json"), ("index_path", "vector_index_e5.json"))},
        "sha256": {path.name: p.sha256(path) for path in (gt, corpus_path, graph_path, index_path)}, "review_status": "pending_human_review"}
    registry_path = ROOT / "configs/runtime_artifacts_live_v2.json"
    p._write(registry_path, registry)
    validate_consumers(p._runtime_sources(registry_path))
    p._write(output.parent.parent / "build_verification.json", {"raw_alignment": stats, "facts_bound": 2,
        "fact_observations": sum(len(f["attributes"].get("source_observations", [])) for f in document["facts"]),
        "cti_chunks": sum(c["chunk_type"] == "cti_report" for c in corpus["chunks"]),
        "unchanged_collections": ["entities", "relationships", "evidence", "sigma_findings", "mitre_assessments", "review", "summary"],
        "embedding": descriptor, "llm_calls": 0, "build_source_sha256": p.sha256(Path(__file__)), "consumers": p._source_manifest(p._runtime_sources(registry_path))})
    print("NEW_MSHTA_GT_CORPUS_GRAPH_E5_VERIFIED; two groups/four source observations; CTI/labels/review unchanged; 0 LLM calls")


if __name__ == "__main__":
    main()
