# DeepSeek: 12 questions × RAG/GraphRAG

Run: deepseek-final-nothinking-20261112T143858Z

Generation: deepseek-flash, thinking disabled, max_tokens 16384, temperature 0.0. Same configuration for both branches.
Integrity, evidence gate, context limits and validator v3.2 remain active. No fallback; maximum one retry for 429/503/timeout.
Context/source receipts preserve exact hashes and source pointers; full duplicate telemetry stays in RAM.

Completed: 24/24; actual HTTP attempts: 15; stopped: no.
Confirmed monetary cost: unknown (provider monetary fields, if present, are retained). accepted_draft is not accuracy.

| Question | Branch | Gate | Eligibility | Outcome | HTTP | Finish |
|---|---|---|---|---|---:|---|
|AUTH-DIRECT|rag|proceed|proceed|accepted_draft|1|stop|
|AUTH-DIRECT|graphrag|proceed|abstain|abstain|0||
|AUTH-CORRELATE|graphrag|proceed|abstain|abstain|0||
|AUTH-CORRELATE|rag|proceed|proceed|accepted_draft|1|stop|
|AUTH-CTI|rag|proceed|proceed|accepted_draft|1|stop|
|AUTH-CTI|graphrag|proceed|proceed|accepted_draft|1|stop|
|AUTH-LIMIT|graphrag|abstain|abstain|abstain|0||
|AUTH-LIMIT|rag|abstain|abstain|abstain|0||
|PS-DIRECT|rag|abstain|abstain|abstain|0||
|PS-DIRECT|graphrag|proceed|proceed|accepted_draft|1|stop|
|PS-CORRELATE|graphrag|proceed|proceed|accepted_draft|1|stop|
|PS-CORRELATE|rag|proceed|proceed|accepted_draft|1|stop|
|PS-CTI|rag|abstain|abstain|abstain|0||
|PS-CTI|graphrag|proceed|proceed|accepted_draft|1|stop|
|PS-LIMIT|graphrag|proceed|proceed|accepted_draft|1|stop|
|PS-LIMIT|rag|abstain|abstain|abstain|0||
|NET-DIRECT|rag|abstain|abstain|abstain|0||
|NET-DIRECT|graphrag|proceed|proceed|accepted_draft|1|stop|
|NET-CORRELATE|graphrag|proceed|proceed|validation_failed|1|stop|
|NET-CORRELATE|rag|proceed|proceed|accepted_draft|1|stop|
|NET-CTI|rag|abstain|abstain|abstain|0||
|NET-CTI|graphrag|proceed|proceed|accepted_draft|1|stop|
|NET-LIMIT|graphrag|proceed|proceed|accepted_draft|1|stop|
|NET-LIMIT|rag|proceed|proceed|accepted_draft|1|stop|

## Branch totals

```json
{
  "rag": {
    "planned": 12,
    "eligible": 6,
    "outcomes": {
      "accepted_draft": 6,
      "abstain": 6
    },
    "http_attempts": 6,
    "token_usage": {
      "prompt_tokens": 107304,
      "completion_tokens": 9101,
      "total_tokens": 116405,
      "prompt_cache_hit_tokens": 21760,
      "prompt_cache_miss_tokens": 85544
    }
  },
  "graphrag": {
    "planned": 12,
    "eligible": 9,
    "outcomes": {
      "abstain": 3,
      "accepted_draft": 8,
      "validation_failed": 1
    },
    "http_attempts": 9,
    "token_usage": {
      "prompt_tokens": 420101,
      "completion_tokens": 13928,
      "total_tokens": 434029,
      "prompt_cache_hit_tokens": 25856,
      "prompt_cache_miss_tokens": 394245
    }
  }
}
```

Sources and citations: each case directory contains context/evidence receipts, attempt/provider_response.json, response.json, and citations.json when a report exists.
Prior truncated trials and earlier accepted MSHTA are preserved separately; they are not merged into this comparison.

Official provider references: https://api-docs.deepseek.com/guides/thinking_mode/ ; https://api-docs.deepseek.com/api/create-chat-completion/

## Verified closeout

Actual usage: {'prompt_tokens': 527405, 'completion_tokens': 23029, 'total_tokens': 550434, 'prompt_cache_hit_tokens': 47616, 'prompt_cache_miss_tokens': 479789}.
Minimum measured gap: 60.109307 seconds.
All 10 original inputs, current code/config/frontend manifest, source consumers and original accepted MSHTA were verified unchanged during this run.
Citations use the actual report schema field evidence_refs; citations_resolved.json preserves those references and validator reference_checks.
No Word edits, full suite, UI redesign, model switch, fallback, or fabricated response.
Evidence gate: 17 proceed / 7 abstain; context budget: 2 additional abstain; final eligibility: 15 proceed / 9 abstain.
Only AUTH-CTI, PS-CORRELATE, NET-CORRELATE and NET-LIMIT have both branches eligible. Eligibility differences must remain visible in any paired comparison.

| Branch | accepted_draft | validation_failed | abstain | truncated | provider_error | not_run | HTTP |
|---|---:|---:|---:|---:|---:|---:|---:|
|rag|6|0|6|0|0|0|6|
|graphrag|8|1|3|0|0|0|9|

## Dashboard / screenshots

Launcher: START_RESULTS_DEEPSEEK.cmd. Catalog: http://127.0.0.1:8034/results .
Direct saved views (0 new API calls):
- mshta-powershell: http://127.0.0.1:8034/view/PS-DIRECT/graphrag
- purplesharp-ad: http://127.0.0.1:8034/view/AUTH-CTI/graphrag
- regsvr32-c2: http://127.0.0.1:8034/view/NET-DIRECT/graphrag

Browser control was blocked because the current URL could not be determined confidently. No new screenshot or visual UI acceptance is claimed.
Open one direct saved URL, wait for accepted_draft and the saved-result/0 API calls label, collapse metadata if needed, then capture the answer, source cards and limits. Existing dividers remain available.
accepted_draft is not semantic accuracy. Abstentions and draft answers still require separate evidence/citation review before thesis claims.
