"""Ingest pinned HTML snapshots into cited, analyst-authored CTI chunks offline."""
from __future__ import annotations

from hashlib import sha256
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
from typing import Any


class ReportText(HTMLParser):
    """Deterministic text view; scripts/styles never become retrieval context."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0
        self.hidden_tags = {"script", "style", "noscript", "svg"}
        self.blocks = {"p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "br", "pre", "tr"}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.hidden_tags:
            self.skip += 1
        if not self.skip and tag in self.blocks:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.hidden_tags:
            self.skip = max(0, self.skip - 1)
        if not self.skip and tag in self.blocks:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)

    def text(self) -> str:
        return "\n".join(line for part in "".join(self.parts).splitlines() if (line := " ".join(part.split()))) + "\n"


def ingest_report(snapshot: Path, metadata: dict, facts: list[dict]) -> tuple[dict, str, list[dict], list[dict]]:
    """Validate bytes and anchor offsets; links cannot assert telemetry truth."""
    content = snapshot.read_bytes()
    source_hash = sha256(content).hexdigest()
    if source_hash != metadata["sha256"]:
        raise ValueError(f"CTI snapshot hash mismatch: {snapshot.name}")
    html = content.decode(metadata["encoding"], errors="strict")
    parser = ReportText()
    parser.feed(html)
    text = parser.text()
    text_hash = sha256(text.encode("utf-8")).hexdigest()
    published = re.findall(r'"datePublished"\s*:\s*"([^"]+)"', html)
    modified = re.findall(r'"dateModified"\s*:\s*"([^"]+)"', html)
    source_id = metadata["source_id"]
    document = {**metadata, "schema_version": "cti-report-source/v1", "snapshot_sha256": source_hash,
                "extracted_text_path": source_id + ".txt", "extracted_text_sha256": text_hash,
                "publication_date": published[0] if published else None,
                "publication_date_basis": "publisher HTML JSON-LD datePublished" if published else "not available",
                "publisher_modified_at": modified[0] if modified else None,
                "date_candidates": {"datePublished": published, "dateModified": modified},
                "date_caveat": "Publisher page metadata; an evolving report URL may retain its initial publication date. Snapshot hash pins the accessed content.",
                "review_status": "pending_human_review", "evidence_layer": "cti_context"}
    chunks, links = [], []
    for fact in facts:
        anchor = fact["anchor"]
        if text.count(anchor) != 1:
            raise ValueError(f"CTI citation anchor must be unique: {snapshot.name}: {anchor!r}")
        start = text.index(anchor)
        if fact.get("excerpt_scope") in {"line", "line_and_next"}:
            start = text.rfind("\n", 0, start) + 1
            end = text.find("\n", start)
            end = len(text) if end < 0 else end
            if fact["excerpt_scope"] == "line_and_next" and end < len(text):
                following = text.find("\n", end + 1)
                end = len(text) if following < 0 else following
            anchor = text[start:end]
        # Source location includes line and character offsets in a hashed text view.
        citation = {"source_id": source_id, "url": metadata["url"], "section": fact["section"],
                    "snapshot_path": metadata["snapshot_path"], "snapshot_sha256": source_hash,
                    "text_path": document["extracted_text_path"], "text_sha256": text_hash,
                    "char_start": start, "char_end": start + len(anchor), "line": text[:start].count("\n") + 1,
                    "anchor": anchor, "offset_unit": "Unicode code points in extracted UTF-8 text; end exclusive"}
        passage = fact.get("publisher_paraphrase", fact.get("text"))
        if not isinstance(passage, str) or not passage.strip():
            raise ValueError(f"CTI passage missing: {snapshot.name}")
        chunk_id = "cti-" + sha256((source_id + source_hash + passage).encode()).hexdigest()[:20]
        chunk = {"chunk_id": chunk_id, "source_id": source_id, "text": passage, "citation": citation,
                       "content_origin": "analyst_paraphrase", "evidence_layer": "cti_context", "status": "candidate",
                       "review_status": "pending_human_review",
                       "scope": "Publisher-reported technical context; does not establish behavior, compromise or C2 purpose in Mordor hosts."}
        if "publisher_paraphrase" in fact:
            chunk.update(content_origin="publisher_paraphrase", publisher_excerpt=anchor,
                         publisher_paraphrase=passage, attribution=metadata["publisher"],
                         citation_role="publisher_source", scope="External publisher context. Paraphrase is analyst wording, not a verbatim quote; only publisher_excerpt is verbatim. Does not establish local telemetry or compromise.")
        chunks.append(chunk)
        analyst = fact.get("analyst_comparison")
        if analyst:
            analyst_id = "cti-" + sha256((source_id + source_hash + "analyst-comparison" + analyst).encode()).hexdigest()[:20]
            chunks.append({"chunk_id": analyst_id, "source_id": source_id, "text": analyst,
                           "analyst_comparison": analyst, "citation": citation, "citation_role": "background_only_not_publisher_attribution",
                           "content_origin": "project_analyst_comparison", "attribution": "Project analyst",
                           "evidence_layer": "cti_context", "status": "candidate", "review_status": "pending_human_review",
                           "scope": "Project analyst interpretation, not publisher text, not observed host telemetry; cannot establish local actor attribution, compromise or C2."})
        for target in fact["context_links"]:
            if target["target_kind"] not in {"technique", "sigma_rule", "behavior"}:
                raise ValueError("CTI context links cannot target observed events or host verdicts")
            links.append({"source_chunk_id": chunk_id, "relationship": "provides_technical_context_for", **target,
                          "status": "candidate", "citation": citation})
    return document, text, chunks, links


def ingest_collection(source_dir: Path, selection: dict, output: Path) -> dict[str, Any]:
    """Build a separate version; never write into runtime retrieval/graph/indexes."""
    if output.exists():
        raise FileExistsError(f"CTI output already exists: {output}")
    output.mkdir(parents=True)
    sources, all_chunks, all_links = [], [], []
    for source_id, facts in sorted(selection.items()):
        metadata = json.loads((source_dir / (source_id + ".fetch.json")).read_text(encoding="utf-8"))
        if metadata["source_id"] != source_id or Path(metadata["snapshot_path"]).name != metadata["snapshot_path"]:
            raise ValueError(f"Invalid CTI source identity/path: {source_id}")
        document, text, chunks, links = ingest_report(source_dir / metadata["snapshot_path"], metadata, facts)
        document["snapshot_path"] = Path(os.path.relpath(source_dir / document["snapshot_path"], output)).as_posix()
        document["fetch_metadata_path"] = Path(os.path.relpath(source_dir / (source_id + ".fetch.json"), output)).as_posix()
        # Normalize artifact-relative citation paths consistently with source manifest.
        for item in chunks + links:
            item["citation"]["snapshot_path"] = document["snapshot_path"]
        (output / document["extracted_text_path"]).write_text(text, encoding="utf-8", newline="\n")
        sources.append(document)
        all_chunks.extend(chunks)
        all_links.extend(links)
    result = {"schema_version": "cti-context-corpus/v1", "review_status": "pending_human_review",
              "evidence_layer": "cti_context", "sources": sources, "chunks": all_chunks, "links": all_links,
              "runtime_integration": "not_performed", "policy": "CTI facts, observed telemetry and assessment remain separate. No IOC transfer or verdict promotion."}
    path = output / "cti_corpus.json"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    assert json.loads(path.read_text(encoding="utf-8")) == result
    return result
