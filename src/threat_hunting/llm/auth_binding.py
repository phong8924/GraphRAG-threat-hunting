"""Bind explicit authentication Status/SubStatus claims to supplied observations.

No dataset value whitelist and no benchmark input. Unparsed/general prose is
reported as outside this bounded check, never certified by a citation's existence.
"""
from __future__ import annotations

import re
from typing import Any, Iterator

from .guardrail import context_catalog
from threat_hunting.retrieval.context_packing import unpack_context

AUTH_EVENTS = {"4625", "4776"}
SECURITY_PROVIDER = "microsoft-windows-security-auditing"
FIELD_VALUE = re.compile(r"\b(substatus|sub status|status)\b\s*[:=]?\s*(0x[0-9a-f]{1,8})\b", re.I)
EVENT = re.compile(r"(?:(?:microsoft-windows-[a-z-]+|security|sysmon)\s+)?(?:(?:event(?:\s+id)?|eid)\s+)?\b(?P<event>4625|4776)\b")
RAW_REF = re.compile(r"jsonl:line:\d+")
ABSENCE = re.compile(r"(?:khong\s+(?:ghi|co)|does not\s+(?:record|have)|no)\s+(substatus|status)\b")


def walk(value: Any) -> Iterator[dict]:
    if isinstance(value, dict):
        if value.get("evidence_layer") == "cti_context":
            return
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def observations(context: dict) -> list[dict]:
    found = {}
    for record in walk(unpack_context(context)):
        original = record.get("original_fields", {})
        canonical = record.get("canonical_fields", {})
        if not isinstance(original, dict) or not isinstance(canonical, dict):
            continue
        event = str(canonical.get("event_id", original.get("EventID", "")))
        if event not in AUTH_EVENTS or not record.get("raw_record_ref"):
            continue
        item = {"event_id": event, "provider": str(canonical.get("provider", original.get("SourceName", ""))).casefold(),
                "source_file": record.get("source_file"), "raw_record_ref": record["raw_record_ref"],
                "status": original.get("Status"), "substatus": original.get("SubStatus")}
        found[(item["source_file"], item["raw_record_ref"], item["provider"])] = item
    return list(found.values())


def same_code(actual: Any, expected: str) -> bool:
    try:
        return actual is not None and int(str(actual), 16) == int(expected, 16)
    except (ValueError, TypeError):
        return False


def check_auth_field_binding(raw: dict, context: dict, normalize) -> dict:
    source = observations(context)
    events = sorted({o["event_id"] for o in source})
    checks, issues = [], []
    catalog = context_catalog(context)
    if not source:
        return {"scope": "no supplied authentication observations; not applicable", "events_in_context": [], "checks": [], "issues": []}
    for field in ("direct_answer", "executive_summary", "technical_analysis", "unverified_claims"):
        texts = raw.get(field, []) if field == "unverified_claims" else [raw.get(field, "")]
        for text in texts:
            for sentence in re.split(r"\n|(?<=[.!?;])\s+", normalize(str(text))):
                claims = list(FIELD_VALUE.finditer(sentence))
                absences = list(ABSENCE.finditer(sentence))
                if not claims and not absences:
                    continue
                mentions = list(EVENT.finditer(sentence))
                # Keep each event's fields and trailing citations in its own segment.
                segments = [(m.start() if i else 0, mentions[i+1].start() if i+1 < len(mentions) else len(sentence), m.group("event")) for i,m in enumerate(mentions)]
                if not segments:
                    segments = [(0, len(sentence), None)]
                elif claims and claims[0].start() < segments[0][0]:
                    segments.insert(0, (0, segments[0][0], mentions[0].group("event") if len(mentions)==1 else None))
                for a,b,event in segments:
                    segment = sentence[a:b]
                    pairs = [(m.group(1).replace(" ", "").lower(), m.group(2).lower()) for m in FIELD_VALUE.finditer(segment)]
                    absent = [m.group(1).lower() for m in ABSENCE.finditer(segment)]
                    if not pairs and not absent:
                        continue
                    inline = list(dict.fromkeys(RAW_REF.findall(segment)))
                    candidates = [o for o in source if event is None or o["event_id"] == event]
                    provider = SECURITY_PROVIDER
                    if "microsoft-windows-sysmon" in segment or re.search(r"\bsysmon\b", segment):
                        provider = "microsoft-windows-sysmon"
                    refs = inline or raw.get("evidence_refs", [])
                    expanded_refs = set(refs)
                    for ref in refs:
                        for item in catalog.get(ref, []):
                            expanded_refs.update(r["raw_record_ref"] for r in walk(item) if r.get("raw_record_ref"))
                    bound = [o for o in candidates if (not refs or o["raw_record_ref"] in expanded_refs) and o["provider"] == provider]
                    # Raw inline citations name exact events; another view cannot witness this claim.
                    wrong_inline = any(not any(o["raw_record_ref"]==ref and (event is None or o["event_id"]==event) and o["provider"]==provider for o in source) for ref in inline)
                    supported = bool(bound) and any(all(same_code(o.get(k),v) for k,v in pairs) and all(o.get(k) is None for k in absent) for o in bound)
                    code = None
                    if wrong_inline:
                        code = "auth_status_citation_mismatch"
                    elif not supported:
                        code = "auth_status_views_merged" if event is None and len(events)>1 else "auth_status_event_mismatch"
                    checks.append({"field": field, "subject_event": event, "provider": provider, "values": pairs, "absent_fields": absent,
                                   "references": inline, "matched_observations": [o["raw_record_ref"] for o in bound],
                                   "status": "unsupported" if code else "supported_inline" if inline else "supported_context_only_inline_binding_unverified"})
                    if code:
                        issues.append({"code": code, "path": field, "reason": "Supplied event/provider/field/value/citation do not jointly support this authentication claim.", "reference": inline or None})
    return {"scope": "explicit EN/VI Status/SubStatus hex assignments and field-absence predicates, scoped by mentioned authentication event/provider and supplied references; all other prose unverified",
            "events_in_context": events, "issues": issues, "checks": checks}
