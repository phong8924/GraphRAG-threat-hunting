"""Bounded EN/VI network-predicate scope, not general natural-language verification.

Inputs are accent-normalized text. A negated account/IP predicate does not negate
a use/transfer predicate. Lists governed by one evidential limitation stay intact.
"""
from __future__ import annotations

import re

TOPIC = re.compile(r"\bc2\b|\bhttp\b|exfiltration")
BOUNDARY = re.compile(r";|[.!?](?:\s|$)|\n|\b(?:but|however|nhung|tuy nhien|whereas)\b")
SUBJECT = r"(?:the\s+)?(?:host|server|actor|machine|workstation|it|they|he|she|we|may tram|may chu|he thong|ke tan cong|c2)\b"
ACTION = re.compile(r"\b(?:use[sd]?|using|send|sent|gui|truyen|dung|su dung|ket noi|connect\w*|communicat\w*|beacon\w*|exfiltrat(?:e[sd]?|ing)|nhan lenh|receiv\w*|bi)\b")
SUBJECT_PREDICATE = SUBJECT + r"\s+(?:(?:da|se|has|had|have|was|is|will)\s+)?(?:" + ACTION.pattern + r"|khong\b|chua\b|not\b|no\b)"
INDEPENDENT = re.compile(r",\s*(?=" + SUBJECT_PREDICATE + r")|\b(?:and|va)\s+(?=(?:(?:no|not|khong|chua)\b|" + SUBJECT_PREDICATE + r"))")
EVIDENTIAL = re.compile(r"(?:khong|chua)\s+(?:(?:the|co|du|duoc|de)\s+)*(?:bang chung|chung minh|thiet lap|xac nhan|xac minh|ket luan|chung thuc)|\b(?:no evidence|cannot|not|never)\s+(?:(?:be|been|yet|sufficient|enough|to|was|is|have|has)\s+)*(?:establish\w*|prov\w*|confirm\w*|verif\w*|demonstrat\w*)|\bno evidence\b")
POST_LIMIT = re.compile(r"(?:khong|chua)\s+(?:(?:duoc|the|co|du)\s+)*(?:xac minh|xac nhan|chung minh|thiet lap|ket luan)|\b(?:unverified|unproven|not established|not proven|not confirmed|not verified|was not established|is not established)\b")
NOMINAL_NEGATION = re.compile(r"(?:\bno\s+(?:(?:confirmed|observed)\s+)?|khong co\s+(?:bang chung ve\s+)?)$")
DIRECT_NEGATION = re.compile(r"(?:\b(?:khong|chua|not|never|cannot)\s+(?:(?:the|duoc|yet|really|actually)\s+){0,2})$")
NOMINAL_ACTION = re.compile(r"(?:ket qua|muc dich|purpose|result|possibility of)[^,;]{0,35}$")


def topic_predicates(value: str, *, lookbehind: int, lookahead: int) -> list[dict]:
    """Classify only explicit network topics; unknown constructions stay unverified."""
    pieces = []
    start = 0
    for match in BOUNDARY.finditer(value):
        pieces.append((start, match.start())); start = match.end()
    pieces.append((start, len(value)))
    clauses = []
    for a, b in pieces:
        start = a
        for match in INDEPENDENT.finditer(value, a, b):
            clauses.append((start, match.start())); start = match.end()
        clauses.append((start, b))
    result = []
    for topic in TOPIC.finditer(value):
        a, b = next(((a, b) for a, b in clauses if a <= topic.start() < b), (0, len(value)))
        clause = value[a:b]
        before = value[max(a, topic.start() - lookbehind):topic.start()]
        after = value[topic.end():min(b, topic.end() + lookahead)]
        # An explicit affirmative operational predicate must have its own negator.
        # A later caveat about an account or source IP cannot govern that predicate.
        actions = list(ACTION.finditer(clause))
        action = next((m for m in reversed(actions) if m.end() <= topic.start() - a), None)
        if action is None:
            action = next((m for m in actions if m.start() >= topic.end() - a and
                re.fullmatch(r"\s*(?:(?:da|se|has|had|have|was|is|will)\s+)?", clause[topic.end()-a:m.start()])), None)
        if action and NOMINAL_ACTION.search(clause[:action.start()]):
            action = None
        evidential = EVIDENTIAL.search(before)
        if action and evidential and max(a, topic.start()-lookbehind) + evidential.start() >= a + action.end():
            # The later evidence predicate, not an earlier unrelated verb, governs this topic.
            action = None
        if action:
            prefix = clause[:action.start()]
            negated_action = bool(DIRECT_NEGATION.search(prefix))
            # "does not prove the host used C2" is a negated evidence predicate,
            # whereas "no source IP, host used C2" has no such governing predicate.
            governed = bool(EVIDENTIAL.search(prefix[-lookbehind:]))
            negated = negated_action or governed
            status = "negated" if negated else "asserted"
        else:
            negated = bool(evidential or NOMINAL_NEGATION.search(before) or POST_LIMIT.search(after) or POST_LIMIT.search(before))
            if not negated and not ACTION.search(clause) and re.search(r",|\b(?:or|hoac|hay)\b", clause):
                # A shared predicate at the end governs the whole nominal list.
                # Bound its search from the final topic rather than an earlier list item.
                last_topic = list(TOPIC.finditer(clause))[-1]
                negated = bool(POST_LIMIT.search(clause[last_topic.end():last_topic.end()+lookahead]))
            status = "negated" if negated else "unverified_topic"
        result.append({"topic": topic.group(), "offset": topic.start(), "clause": clause.strip(),
                       "predicate": action.group() if action else "evidence_limit_or_topic",
                       "negated": negated, "status": status})
    return result
