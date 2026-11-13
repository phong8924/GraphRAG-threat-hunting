"""Question-focused policy with bounded clock/scope checks, no benchmark input."""
from __future__ import annotations

from copy import deepcopy
import json
import os
import re
import unicodedata
from typing import Any

from . import generation_contract as source

CONTRACT = "source-meaning/v3"
INSTRUCTIONS = """
QUESTION FOCUS AND CLOCK POLICY source-meaning/v3:
- Answer every requested part, using only the supplied source fields. Do not substitute a
  general safety disclaimer for the requested facts or comparison. Do not add unrelated
  HTTP/C2/exfiltration caveats when the question does not concern network behavior.
- For a requested telemetry/CTI comparison, explicitly separate: local telemetry with its
  references; publisher/report context with separate references; similarities; differences
  in the behavior/distribution actually described; and limits. Explain both similarities
  AND differences. A difference in document detail is not a substitute for comparing the
  requested behavior. If a comparison dimension is absent in the returned sources, say
  which dimension cannot be compared; do not invent it. This is an answer structure,
  not a finding, actor attribution or reference answer.
- When reporting a time interval from authentication records, explicitly call it a
  'khoảng dấu thời gian canonical của các observations/anchors được chọn'. Do not call
  it the duration, start or end of the actual attack/activity. Event timestamps, actual
  activity duration and cross-host clock synchronization are different propositions.
  Raw timestamps and clock caveats remain; no time correction is authorized.
- sigma_matches copies exact source rule_id values; finding IDs and graph node IDs are
  citation identifiers only. Keep observed actor/action separate from command text and
  unobserved completion. Candidate/review status never becomes human confirmation.
- CTI publisher_excerpt is verbatim source; publisher_paraphrase is analyst paraphrase of the publisher.
  analyst_comparison is project interpretation, never a publisher quote or observed host telemetry.
- Keep optional report fields empty when they add nothing required by the question.
  Citations must bind the claim in the same clause. The report remains a reviewable draft.
- Return a concise JSON report without a reasoning trace. Answer the requested parts
  with inline source references and necessary uncertainty; avoid repeating the same
  analysis across fields. Do not omit required evidence, schema fields or limitations.
"""


def normalize(value: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", value.casefold().replace("đ", "d"))
                   if unicodedata.category(c) != "Mn")


def query_text(context: dict[str, Any]) -> str:
    query = context.get("query", {})
    return query.get("text", "") if isinstance(query, dict) else str(query)


def question_focus(query: str) -> dict[str, bool]:
    value = normalize(query)
    return {"comparison_requested": bool(re.search(r"doi chieu|so sanh|compar", value)),
            "network_requested": bool(re.search(r"\bc2\b|\bhttp\b|exfil|\bnetwork\b|ket noi|\bmang\b|download|scriptlet|\burl\b", value))}


_NETWORK_TOPIC = re.compile(r"\bc2\b|\bhttp\b|exfiltration")


def _env_int(name: str, default: int, maximum: int | None = None) -> int:
    """Read a bounded positive int from environment; fall back to default on bad input.

    Read directly from ``os.environ`` on purpose: importing the LLM config module
    here would create a circular import. ``maximum`` enforces the upper bound that the
    previous implementation advertised in prose but never applied.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return min(value, maximum) if maximum is not None else value


def network_topic_spans(value: str) -> list[dict[str, Any]]:
    from .predicate_negation import topic_predicates
    return topic_predicates(value,
        lookbehind=_env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400),
        lookahead=_env_int("VALIDATOR_NETWORK_LOOKAHEAD", 80, 400))


def is_negated_network_statement(value: str) -> bool:
    """Every topic must be governed by its own negated predicate; unknowns are not caveats."""
    detail = network_topic_spans(value)
    return bool(detail) and all(item["negated"] for item in detail)


def annotate_context(context: dict[str, Any]) -> dict[str, Any]:
    result = source.annotate_context(context)
    result["generation_evidence_contract"]["schema_version"] = CONTRACT
    return result


def build_messages(query: str, context: dict[str, Any]) -> list[dict[str, str]]:
    messages = source.build_messages(query, context)
    messages[0]["content"] += INSTRUCTIONS
    messages[1]["content"] += "\n[QUESTION FOCUS — derived from user request, not evaluation criteria]\n" + json.dumps(question_focus(query))
    return messages


def check_clock_and_scope(raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    projection = source.project_meaning(context)
    auth = bool(projection["timestamp_semantics"]["source_clock_groups"])
    focus = question_focus(query_text(context))
    issues, checks = [], []
    for field in ("direct_answer", "executive_summary", "technical_analysis", "unverified_claims"):
        texts = raw.get(field, []) if field == "unverified_claims" else [raw.get(field, "")]
        for text in texts:
            for sentence in re.split(r"\n|(?<=[.!?])\s+|;", text):
                value = normalize(sentence)
                # Only explicit duration expressions with numeric units are classified.
                match = re.search(r"(?:thoi luong|keo dai|duration|lasted)[^\n]{0,65}?\d+(?:[.,]\d+)?\s*(?:mili.?giay|milliseconds?|\bms\b|giay|seconds?|\bs\b)", value)
                if auth and match:
                    prefix = value[:match.start()]
                    negative = bool(re.search(r"khong|chua|not|cannot|unverified", prefix))
                    canonical_scope = bool(re.search(r"(?:canonical|timestamp|dau thoi gian|observation|anchor)", value))
                    physical = bool(re.search(r"thoi luong (?:cua )?(?:cuoc|dot|cum)?\s*(?:tan cong|hoat dong)|(?:attack|activity) duration|(?:attack|activity) lasted", value))
                    supported = negative or (canonical_scope and not physical)
                    checks.append({"field": field, "kind": "numeric_duration_expression", "status": "scoped_or_negated" if supported else "unsupported_physical_inference"})
                    if not supported:
                        issues.append({"code": "unsupported_physical_duration_inference", "path": field,
                            "reason": "A canonical observation/anchor span does not establish physical activity duration.", "reference": None})
                if not focus["network_requested"] and _NETWORK_TOPIC.search(value):
                    if is_negated_network_statement(value):
                        checks.append({"field": field, "kind": "unrequested_network_topic", "status": "negated_boundary_caveat"})
                    else:
                        checks.append({"field": field, "kind": "unrequested_network_topic", "status": "outside_request"})
                        issues.append({"code": "unrequested_network_claim", "path": field,
                            "reason": "This explicit network topic is asserted outside the requested answer scope; negated boundary caveats are allowed.", "reference": None})
    return {"scope": "explicit numeric authentication-duration expressions and asserted HTTP/C2/exfiltration topics only; negated boundary caveats are permitted",
            "checks": checks, "issues": issues, "comparison_semantics": "requires offline rubric review, not automatically verified",
            "remaining_prose": "unverified; AI/human semantic review remains necessary"}


def validate_meaning(checked: dict[str, Any], raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    result = source.validate_meaning(checked, raw, context)
    audit = check_clock_and_scope(raw, context)
    result["clock_and_scope_audit"] = audit
    result["issues"].extend(audit["issues"])
    # F02: a cited object ID does not prove a field claim; bind Status/SubStatus to the event.
    binding = check_auth_field_binding(raw, context)
    result["auth_field_binding_audit"] = binding
    result["issues"].extend(binding["issues"])
    if audit["issues"] or binding["issues"]:
        result["status"] = "validation_failed"
        result["sanitized_report"]["verdict"] = "INSUFFICIENT_EVIDENCE"
    result["scope"] = ("structured claims + bounded process citation, duration, request-topic and "
                       "authentication Status/SubStatus binding checks; remaining prose/comparison "
                       "correctness unverified")
    return result


def check_auth_field_binding(raw: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    from .auth_binding import check_auth_field_binding as bind_observations
    return bind_observations(raw, context, normalize)


# --- F03: effective validator policy --------------------------------------------------
# Any parameter that can change a validation outcome must be visible to the runtime pin, so a
# frozen study cannot be described by two different validator behaviours.
VALIDATOR_POLICY_ID = "source-meaning-validator/v3.2"


def effective_validator_policy() -> dict[str, Any]:
    """Return the exact validator parameters in force, with applied bounds."""
    return {
        "policy_id": VALIDATOR_POLICY_ID,
        "network_lookbehind": _env_int("VALIDATOR_NETWORK_LOOKBEHIND", 120, 400),
        "network_lookahead": _env_int("VALIDATOR_NETWORK_LOOKAHEAD", 80, 400),
        "lookbehind_bounds": [1, 400],
        "lookahead_bounds": [1, 400],
        "negation_scope": "clause-local",
        "clause_split": "sentence|contrast|subject-comma|independent-and-va",
        "negation_binding": "topic-specific evidential/use predicate; unrelated negators do not govern the topic",
        "authentication_binding": "supplied event/provider/field/value/reference; no dataset value whitelist",
        "unverified_scope": "all prose outside the finite EN/VI predicate and Status/SubStatus grammar",
        "checks": [
            "numeric_duration_expression",
            "unrequested_network_topic",
            "auth_status_event_binding",
            "auth_status_views_merged",
        ],
        "source_contract": f"{source.CONTRACT if hasattr(source, 'CONTRACT') else 'inherited'}/v3",
    }
