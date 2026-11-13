import hashlib
import json

import pytest

from threat_hunting.cti.ingestion import ingest_report, ingest_collection


def fixture_source(tmp_path):
    content = ('<html><script type="application/ld+json">{"datePublished":"2020-01-02"}</script>'
               '<style>hidden</style><h1>Fixture report</h1><h2>Analysis</h2>'
               '<p>A unique technical anchor describes context.</p><p>Unicode: tiếng Việt.</p></html>').encode()
    snapshot = tmp_path / "fixture.html"
    snapshot.write_bytes(content)
    metadata = {"source_id": "fixture", "snapshot_path": snapshot.name, "sha256": hashlib.sha256(content).hexdigest(),
                "encoding": "utf-8", "publisher": "Synthetic fixture", "url": "https://example.invalid/report", "accessed_at": "2026-10-30T00:00:00Z"}
    facts = [{"anchor": "unique technical anchor", "section": "Analysis", "text": "Synthetic technical context; no telemetry claim.",
              "context_links": [{"target_kind": "behavior", "target_id": "fixture-behavior"}]}]
    return snapshot, metadata, facts


def test_snapshot_hash_citations_unicode_and_determinism(tmp_path):
    snapshot, metadata, facts = fixture_source(tmp_path)
    before = snapshot.read_bytes()
    result = ingest_report(snapshot, metadata, facts)
    doc, text, chunks, links = result
    assert doc["publication_date"] == "2020-01-02"
    assert 'datePublished' not in text and 'hidden' not in text
    assert 'tiếng Việt' in text
    cite = chunks[0]["citation"]
    assert text[cite["char_start"]:cite["char_end"]] == facts[0]["anchor"]
    assert chunks[0]["evidence_layer"] == "cti_context"
    assert links[0]["relationship"] == "provides_technical_context_for"
    assert ingest_report(snapshot, metadata, facts) == result
    assert snapshot.read_bytes() == before


def test_cti_hash_and_nonunique_anchor_fail(tmp_path):
    snapshot, metadata, facts = fixture_source(tmp_path)
    metadata["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash mismatch"):
        ingest_report(snapshot, metadata, facts)
    metadata["sha256"] = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    facts[0]["anchor"] = "not present"
    with pytest.raises(ValueError, match="anchor must be unique"):
        ingest_report(snapshot, metadata, facts)


def test_cti_cannot_link_to_observed_host_verdict(tmp_path):
    snapshot, metadata, facts = fixture_source(tmp_path)
    facts[0]["context_links"][0]["target_kind"] = "host"
    with pytest.raises(ValueError, match="cannot target observed events"):
        ingest_report(snapshot, metadata, facts)


def test_collection_new_only_paths_and_readback(tmp_path):
    snapshot, metadata, facts = fixture_source(tmp_path)
    (tmp_path / "fixture.fetch.json").write_text(json.dumps(metadata), encoding="utf-8")
    output = tmp_path / "cti"
    result = ingest_collection(tmp_path, {"fixture": facts}, output)
    assert json.loads((output / "cti_corpus.json").read_text(encoding="utf-8")) == result
    assert result["runtime_integration"] == "not_performed"
    assert (output / result["sources"][0]["snapshot_path"]).resolve() == snapshot.resolve()
    with pytest.raises(FileExistsError):
        ingest_collection(tmp_path, {"fixture": facts}, output)


def test_publisher_excerpt_paraphrase_and_project_comparison_are_separate_chunks(tmp_path):
    snapshot, metadata, facts = fixture_source(tmp_path)
    facts[0].pop("text")
    facts[0].update(publisher_paraphrase="Paraphrase of the publisher.",
                    analyst_comparison="Project interpretation, not publisher text.", excerpt_scope="line")
    before = snapshot.read_bytes()
    doc, text, chunks, links = ingest_report(snapshot, metadata, facts)
    publisher, analyst = chunks
    assert publisher["content_origin"] == "publisher_paraphrase"
    assert analyst["content_origin"] == "project_analyst_comparison"
    assert "Project interpretation" not in publisher["text"]
    citation = publisher["citation"]
    assert publisher["publisher_excerpt"] == text[citation["char_start"]:citation["char_end"]]
    assert analyst["attribution"] == "Project analyst"
    assert analyst["citation_role"] == "background_only_not_publisher_attribution"
    assert snapshot.read_bytes() == before


def test_analyst_comparison_is_not_a_publisher_gate_witness():
    from copy import deepcopy
    from pathlib import Path
    from threat_hunting.evaluation.evidence_contract_v2 import assess_integrated_evidence_gate
    from threat_hunting.retrieval.context_packing import unpack_context
    root = Path(__file__).resolve().parents[1]
    context = unpack_context(json.loads((root / "outputs/experiments/integrated-final-v19-live-01/AUTH-CTI_graphrag/context.json").read_text(encoding="utf-8")))
    legacy = json.loads((root / "outputs/final/20261101_direct_v19/preflight/AUTH-CTI_graphrag/legacy_gate.json").read_text(encoding="utf-8"))
    from threat_hunting.evaluation.evidence_contract import walk
    # Call the real gate first, then change only the origin tag of publisher-bearing objects.
    before_gate, before = assess_integrated_evidence_gate(context["query"]["text"], context, legacy)
    changed = deepcopy(context)
    for obj, _ in walk(changed):
        if obj.get("publisher") and isinstance(obj.get("citation"), dict):
            obj["content_origin"] = "project_analyst_comparison"
    after_gate, after = assess_integrated_evidence_gate(context["query"]["text"], changed, legacy)
    def checks(gate):
        # The source contract publishes its finite witness audit under source_evidence.
        return [v for v,_ in walk(gate) if v.get("requirement") == "external_cti_context"]
    assert any(v["status"] == "supported" for v in checks(before_gate))
    assert checks(after_gate) and all(v["status"] == "missing" for v in checks(after_gate))
