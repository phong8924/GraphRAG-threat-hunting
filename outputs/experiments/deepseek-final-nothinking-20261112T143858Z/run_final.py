"""User-authorized current-source 12x2 run. Final non-thinking configuration; durable sequential generation and at most one transient retry."""
from __future__ import annotations
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import argparse
import csv
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
for variable in ('HF_HUB_OFFLINE', 'TRANSFORMERS_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY', 'HF_HUB_DISABLE_IMPLICIT_TOKEN'):
    os.environ[variable] = '1'
from scripts.current_interactive_runtime import verify_current_manifest
from scripts.interactive_runtime import evidence_references
from threat_hunting.evaluation import experimental_comparison as p
from threat_hunting.evaluation.final_experiment import snapshot
from threat_hunting.server.experimental import ExperimentalRequest, response_payload

CONFIG_PATH = ROOT / 'configs/interactive/dashboard_live_v10.json'
PIN_PATH = ROOT / 'configs/interactive/runtime_manifest_live_v9.json'
MODEL = replace(p.LLMConfig.from_env(), max_retries=1)
ENV_HASH = p.sha256(ROOT / '.env')  # in memory only; never write credentials/env contents
CONFIG = p._read(CONFIG_PATH)
PIN = p._read(PIN_PATH)
RAW_CASES = p._read(ROOT / CONFIG['benchmark'])
CASES = RAW_CASES['cases']
PATHS = p._runtime_sources(ROOT / CONFIG['runtime_artifacts'])
PERSISTENCE_ERRORS = []
INTERVAL = float(os.environ.get('RUN_REQUEST_INTERVAL_SECONDS') or
                 p._read(ROOT / 'configs/evaluation/integrated_final_direct_v7.json')['final_run_policy']['request_interval_seconds'])
assert math.isfinite(INTERVAL) and INTERVAL > 0
assert MODEL.base_url == 'https://api.deepseek.com' and MODEL.model_name == 'deepseek-flash'
assert MODEL.thinking == 'disabled' and MODEL.max_tokens == 16384
assert len(CASES) == 12 and len({c['case_id'] for c in CASES}) == 12


def utc():
    return datetime.now(timezone.utc).isoformat()


def safe(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if re.fullmatch(r'(?i)(api[_-]?key|authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|password|secret)', str(k)) else safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    if isinstance(value, str):
        value = value.replace(MODEL.api_key, '[REDACTED]') if MODEL.api_key else value
        return re.sub(r'\bsk-[A-Za-z0-9_-]{12,}|AIza[A-Za-z0-9_-]{25,}|(?i:Bearer)\s+[^\s,;"\x27}]+', '[REDACTED]', value)
    return value


def write(path, value):
    raw = p.canonical_bytes(value)
    if MODEL.api_key and MODEL.api_key.encode() in raw:
        raise ValueError('Refuse to persist credential')
    memory_artifacts = {'context', 'messages', 'evidence_contract', 'gate', 'legacy_gate', 'signals', 'eligibility'}
    if path.stem in memory_artifacts:
        case_id = path.parent.name.rsplit('_', 1)[0]
        sid = next(case['scenario_id'] for case in CASES if case['case_id'] == case_id)
        receipt = {'schema_version': 'current-paired-input-receipt/v1', 'artifact': path.stem,
            'content_sha256': hashlib.sha256(raw).hexdigest(), 'content_utf8_bytes': len(raw),
            'scenario_id': sid, 'source_bindings': p._source_manifest({sid: PATHS[sid]})[sid],
            'persistence': 'Exact runtime value stays in RAM; source objects remain in unchanged pinned consumers. No duplicate raw payload persisted.'}
        if path.stem == 'evidence_contract':
            receipt['evidence'] = evidence_references(value, PATHS[sid])
        if path.stem in {'gate', 'legacy_gate', 'eligibility'}:
            receipt['decision_metadata'] = {key: value[key] for key in ('decision', 'reason_codes', 'abstention_stage', 'stage', 'budget_exceeded', 'context_utf8_bytes', 'messages_utf8_bytes') if key in value}
        p._write(path.with_name(path.stem + '_receipt.json'), receipt)
        return
    try:
        p._write(path, value)
    except OSError as error:
        PERSISTENCE_ERRORS.append({'file': path.relative_to(OUT).as_posix(), 'error_type': type(error).__name__, 'errno': error.errno})
        raise


def integrity():
    if p.sha256(ROOT / '.env') != ENV_HASH:
        raise ValueError('Environment file changed during this process')
    verify_current_manifest(CONFIG_PATH, PIN_PATH, validate_schema=False)


def prepare():
    integrity()
    verify_current_manifest(CONFIG_PATH, PIN_PATH, validate_schema=True)
    paths = p._runtime_sources(ROOT / CONFIG['runtime_artifacts'])
    raw = p._read(ROOT / 'packaging/inputs.json')['inputs']
    for item in raw:
        source = ROOT / item['path']
        if not source.is_file():
            raise FileNotFoundError(item['filename'])
        if source.stat().st_size != item['size_bytes'] or p.sha256(source) != item['sha256']:
            raise ValueError('Raw input integrity: ' + item['filename'])
    protocol = {'schema_version': 'current-source-paired-run/v1', 'run_id': OUT.name, 'created_utc': utc(),
        'source_config': CONFIG_PATH.relative_to(ROOT).as_posix(), 'source_config_sha256': p.sha256(CONFIG_PATH),
        'source_manifest': PIN_PATH.relative_to(ROOT).as_posix(), 'source_manifest_sha256': p.sha256(PIN_PATH),
        'source_configuration_frozen_for_run': True, 'model': p._safe_config(MODEL),
        'cases_path': CONFIG['benchmark'], 'cases_sha256': p.sha256(ROOT / CONFIG['benchmark']),
        'code_sha256': p._code_manifest(), 'frontend_sha256': PIN['frontend_sha256'], 'artifacts': p._source_manifest(paths),
        'gate_policy_sha256': p.sha256(ROOT / CONFIG['gate_policy']), 'raw_inputs': raw,
        'planned_questions': 12, 'planned_branches': 24, 'maximum_authorized_http_attempts': None,
        'request_interval_seconds': INTERVAL, 'interval_basis': 'RUN_REQUEST_INTERVAL_SECONDS or existing project final_run_policy default60',
        'automatic_retry': False, 'fallback': False, 'maximum_transient_retries_per_pair': 1,
        'execution_boundary': 'New user-authorized batch with current shared prepare_branch/generate_branch. Interactive cap6 and historical frozen-study cap20/ledgers are not modified or reused.',
        'stop_policy': {'immediate_http': [401,402,403], 'transient_retry_once': [429,503,'timeout'], 'persistent_service_errors': 'stop after unsuccessful transient recovery'},
        'semantic_accuracy': 'not measured by accepted_draft; pending independent review',
        'usage_cost_policy': 'Retain provider-returned usage/money only. No invented tokens, balance deltas or price estimates.',
        'script_sha256': p.sha256(Path(__file__)), 'historical_results_unchanged': True}
    protocol['input_persistence'] = 'Project evidence_references receipts: full context/messages/gate contract in RAM, exact hashes and consumer pointers persisted. No Defender changes or quarantined artifacts restored.'
    write(OUT / 'execution_manifest.json', protocol)
    write(OUT / 'source_configuration.json', CONFIG)
    write(OUT / 'source_runtime_manifest.json', PIN)
    write(OUT / 'cases_evaluation_only.json', RAW_CASES)
    policy_doc = p._read(ROOT / CONFIG['gate_policy'])
    policy = {key: policy_doc[key] for key in ('schema_version', 'policy_id', 'topical_relevance', 'evidence_answerability')}
    backends, rows, warmups = {}, [], {}
    for index, case in enumerate(CASES):
        order = p.BRANCHES if index % 2 == 0 else tuple(reversed(p.BRANCHES))
        for branch in order:
            started = time.perf_counter()
            directory = OUT / (case['case_id'] + '_' + branch)
            directory.mkdir()
            emit = lambda name, value: write(directory / (name + '.json'), value)
            row = {'question_id': case['case_id'], 'case_id': case['case_id'], 'scenario_id': case['scenario_id'],
                'branch': branch, 'query': case['request']['query'], 'outcome': 'runtime_error',
                'gate_decision': None, 'eligibility_decision': None, 'context_utf8_bytes': None, 'messages_utf8_bytes': None,
                'llm_http_attempts': 0, 'fallback_used': False, 'human_review_required': True,
                'prepared_utc': utc(), 'provider_usage': None, 'provider_reported_cost': None}
            try:
                source = paths[case['scenario_id']]
                corpus = p.load_retrieval_corpus(source['corpus_path'])
                scope = p.assess_query_scope(case['request']['query'], corpus=corpus, graph={})
                emit('scope', scope)
                if scope['decision'] == 'abstain':
                    row.update(outcome='abstain', gate_decision='abstain', eligibility_decision='abstain',
                        abstention_stage='query_scope', abstention_reason_codes=scope.get('reason_codes', []))
                else:
                    vector = p.load_vector_index(source['index_path'])
                    embedding = vector['embedding']
                    key = embedding['model_id'] + '@' + embedding['model_revision']
                    if key not in backends:
                        backend = p.SentenceTransformerEmbeddingBackend(model_id=embedding['model_id'], model_revision=embedding['model_revision'],
                            dimension=embedding['dimension'], device='cpu', batch_size=32, show_progress_bar=False)
                        warm = time.perf_counter(); backend.load(); warmups[key] = time.perf_counter() - warm
                        backends[key] = backend
                    prepared = p.prepare_branch(case['request']['query'], branch, source, corpus, vector, backends[key], CONFIG, policy, emit)
                    row.update(prepared['row'])
                    if branch == 'graphrag' and case['case_id'] in ('AUTH-DIRECT', 'AUTH-CORRELATE'):
                        from threat_hunting.retrieval.context_packing import pack_context, unpack_context
                        original = prepared['context']
                        candidate = pack_context(unpack_context(original))
                        audit = {'original_bytes': len(p.canonical_bytes(original)), 'existing_lossless_repack_bytes': len(p.canonical_bytes(candidate)),
                            'expanded_content_identical': unpack_context(candidate) == unpack_context(original),
                            'context_limit_unchanged': CONFIG['maximum_context_utf8_bytes'],
                            'decision': 'Retain current serialization. Existing interning already applies before annotation; no evidence removal or budget increase.'}
                        for kind in ('nodes','edges'):
                            items=original['traversal'].get(kind,[])
                            ids=[item.get('id',item.get(kind[:-1]+'_id')) for item in items]
                            audit[kind+'_count']=len(items)
                            audit[kind+'_duplicate_ids']=len(ids)-len(set(ids))
                        emit('context_serialization_audit', audit)

                    if prepared['budget_exceeded']:
                        row.update(outcome='abstain', eligibility_decision='abstain', abstention_stage='context_budget', budget_exceeded=True)
                    elif prepared['gate']['decision'] == 'abstain':
                        row['outcome'] = 'abstain'
                    else:
                        row['outcome'] = 'not_run'
                    row['abstention_reason_codes'] = (['context_utf8_budget_exceeded' if row['context_utf8_bytes'] > CONFIG['maximum_context_utf8_bytes'] else 'messages_utf8_budget_exceeded'] if prepared['budget_exceeded'] else prepared['gate'].get('reason_codes', [])) if row['outcome'] == 'abstain' else []
                row['preparation_seconds'] = time.perf_counter() - started
            except Exception as error:
                row.update(outcome='runtime_error', preparation_error_type=type(error).__name__, preparation_error=safe(str(error)))
            emit('preflight_result', row)
            rows.append(row)
            print(json.dumps({'phase': 'prepare', 'question_id': row['question_id'], 'branch': branch,
                'gate': row['gate_decision'], 'eligibility': row['eligibility_decision'], 'outcome': row['outcome'],
                'context_bytes': row['context_utf8_bytes'], 'messages_bytes': row['messages_utf8_bytes']}, ensure_ascii=True), flush=True)
    assert len(rows) == 24 and len({(r['case_id'], r['branch']) for r in rows}) == 24
    pair_audit = []
    for case in CASES:
        selected = {r['branch']: r for r in rows if r['case_id'] == case['case_id']}
        hashes = [selected[b].get('retrieval_sha256') for b in p.BRANCHES]
        identical = hashes[0] == hashes[1] if all(hashes) else None
        pair_audit.append({'question_id': case['case_id'], 'identical_hybrid_retrieval': identical})
    write(OUT / 'paired_retrieval_audit.json', {'rows': pair_audit})
    write(OUT / 'preflight_results.json', {'prepared_branches': len(rows), 'llm_http_attempts': 0, 'warmups': warmups,
        'eligible_branches': sum(r['eligibility_decision'] == 'proceed' for r in rows), 'rows': rows})
    if any(r['outcome'] == 'runtime_error' for r in rows) or any(r['identical_hybrid_retrieval'] is False for r in pair_audit):
        raise ValueError('Preparation failed; no provider requests authorized to start')
    integrity()
    print(json.dumps({'phase': 'prepare_complete', 'prepared': 24, 'eligible': sum(r['eligibility_decision'] == 'proceed' for r in rows), 'llm_attempts': 0}), flush=True)


def provider_cost(document):
    values = []
    for prefix, item in (('', document), ('usage.', document.get('usage', {}))):
        if not isinstance(item, dict):
            continue
        for key in ('cost', 'total_cost', 'cost_usd', 'total_cost_usd', 'input_cost', 'output_cost'):
            value = item.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
                values.append({'field': prefix + key, 'value': value,
                    'currency': 'USD' if key.endswith('_usd') else item.get('currency', document.get('currency'))})
    return values or None


def rebuild(row, backends):
    source = PATHS[row['scenario_id']]
    corpus = p.load_retrieval_corpus(source['corpus_path'])
    vector = p.load_vector_index(source['index_path'])
    embedding = vector['embedding']; key = embedding['model_id'] + '@' + embedding['model_revision']
    if key not in backends:
        backend = p.SentenceTransformerEmbeddingBackend(model_id=embedding['model_id'], model_revision=embedding['model_revision'],
            dimension=embedding['dimension'], device='cpu', batch_size=32, show_progress_bar=False)
        backend.load(); backends[key] = backend
    artifacts = {'scope': p.assess_query_scope(row['query'], corpus=corpus, graph={})}
    doc = p._read(ROOT / CONFIG['gate_policy'])
    policy = {k: doc[k] for k in ('schema_version', 'policy_id', 'topical_relevance', 'evidence_answerability')}
    prepared = p.prepare_branch(row['query'], row['branch'], source, corpus, vector, backends[key], CONFIG, policy,
        lambda name, value: artifacts.__setitem__(name, deepcopy(value)))
    for name in ('context', 'messages'):
        assert hashlib.sha256(p.canonical_bytes(prepared[name])).hexdigest() == row[name+'_sha256']
    assert prepared['gate']['decision'] == row['gate_decision']
    return prepared, artifacts


def live():
    integrity()
    protocol = p._read(OUT / 'execution_manifest.json')
    assert protocol['script_sha256'] == p.sha256(Path(__file__))
    assert p._safe_config(MODEL) == protocol['model']
    preflight = p._read(OUT / 'preflight_results.json')
    if (OUT / 'results.json').exists():
        previous = p._read(OUT / 'results.json')
        rows = previous['rows']; attempts = p._read(OUT / 'attempts.json')['attempts']
        if any(a.get('actual_http_attempts') is None for a in attempts):
            raise ValueError('Unresolved reserved attempt; inspect saved artifacts before resuming, never call it again blindly')
        if previous.get('stopped_reason'):
            raise ValueError('Previous run stopped for a real blocker; diagnose before resuming')
    else:
        rows = deepcopy(preflight['rows']); attempts = []
    stopped = None; backends = {}; pacer = p.RequestPacer(INTERVAL)
    ledger_path = OUT / 'attempts.json'

    def checkpoint():
        by_branch = {}
        for branch in p.BRANCHES:
            selected = [r for r in rows if r['branch'] == branch]
            totals = Counter()
            for a in attempts:
                if a['branch'] == branch:
                    for key, value in (a.get('usage') or {}).items():
                        if isinstance(value, (int,float)) and not isinstance(value,bool): totals[key] += value
            by_branch[branch] = {'planned': len(selected), 'eligible': sum(r['eligibility_decision']=='proceed' for r in selected),
                'outcomes': dict(Counter(r['outcome'] for r in selected)),
                'http_attempts': sum(a.get('actual_http_attempts') or 0 for a in attempts if a['branch']==branch), 'token_usage': dict(totals)}
        terminal = {'accepted_draft','validation_failed','abstain','truncated_response','provider_error','rate_limited','runtime_error','persistence_error'}
        result = {'schema_version': 'current-paired-results/v2', 'run_id': OUT.name, 'updated_utc': utc(),
            'planned_branches': 24, 'prepared_branches': 24, 'completed_branches': sum(r['outcome'] in terminal for r in rows),
            'eligible_branches': preflight['eligible_branches'], 'http_attempts': sum(a.get('actual_http_attempts') or 0 for a in attempts),
            'maximum_authorized_http_attempts': None, 'request_interval_seconds': INTERVAL, 'stopped_reason': stopped,
            'model': protocol['model'], 'by_branch': by_branch, 'confirmed_monetary_cost': None,
            'cost_status': 'Unknown unless provider returns monetary fields; tokens are actual provider usage, not cost zero.',
            'semantic_accuracy': 'Not assessed. accepted_draft means existing structured/meaning validation passed; human review remains required.', 'rows': rows}
        snapshot(OUT/'results.json', result)
        snapshot(ledger_path, {'maximum_authorized': None, 'maximum_transient_retries_per_pair': 1, 'attempts': attempts, 'stopped_reason': stopped})
        fields = ('question_id','scenario_id','branch','outcome','gate_decision','eligibility_decision','abstention_stage','abstention_reason_codes',
            'context_utf8_bytes','messages_utf8_bytes','context_sha256','messages_sha256','llm_http_attempts','finish_reason','validation_status',
            'provider_http_seconds','generation_validation_seconds','provider_usage','provider_reported_cost','provider_error','response_path','citations_path')
        temp = OUT/'results.csv.tmp'
        with temp.open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');writer.writeheader()
            for r in rows: writer.writerow({k:json.dumps(r.get(k),ensure_ascii=False) if isinstance(r.get(k),(dict,list)) else r.get(k) for k in fields})
        os.replace(temp,OUT/'results.csv')
        text=['# DeepSeek: 12 questions × RAG/GraphRAG', '', 'Run: '+OUT.name,
            '', 'Generation: deepseek-flash, thinking disabled, max_tokens 16384, temperature 0.0. Same configuration for both branches.',
            'Integrity, evidence gate, context limits and validator v3.2 remain active. No fallback; maximum one retry for 429/503/timeout.',
            'Context/source receipts preserve exact hashes and source pointers; full duplicate telemetry stays in RAM.',
            '', f"Completed: {result['completed_branches']}/24; actual HTTP attempts: {result['http_attempts']}; stopped: {stopped or 'no'}.",
            'Confirmed monetary cost: unknown (provider monetary fields, if present, are retained). accepted_draft is not accuracy.',
            '', '| Question | Branch | Gate | Eligibility | Outcome | HTTP | Finish |', '|---|---|---|---|---|---:|---|']
        text += [f"|{r['question_id']}|{r['branch']}|{r.get('gate_decision')}|{r.get('eligibility_decision')}|{r['outcome']}|{r['llm_http_attempts']}|{r.get('finish_reason','')}|" for r in rows]
        text += ['', '## Branch totals', '', '```json',json.dumps(by_branch,indent=2,ensure_ascii=False),'```',
            '', 'Sources and citations: each case directory contains context/evidence receipts, attempt/provider_response.json, response.json, and citations.json when a report exists.',
            'Prior truncated trials and earlier accepted MSHTA are preserved separately; they are not merged into this comparison.',
            '', 'Official provider references: https://api-docs.deepseek.com/guides/thinking_mode/ ; https://api-docs.deepseek.com/api/create-chat-completion/']
        (OUT/'report.md').write_text('\n'.join(text)+'\n',encoding='utf-8')
        return result

    checkpoint()
    for row in rows:
        directory = OUT/(row['case_id']+'_'+row['branch'])
        if row['outcome'] not in {'not_run','not_run_after_stop'}:
            snapshot(directory/'result.json',row);continue
        if stopped:
            row.update(outcome='not_run_after_stop',not_run_reason=stopped)
            snapshot(directory/'result.json',row);checkpoint();continue
        if (OUT/'STOP_REQUESTED').exists():
            stopped='user_stop_requested';row.update(outcome='not_run_after_stop',not_run_reason=stopped);checkpoint();continue
        integrity()
        rebuilt, base_artifacts = rebuild(row,backends)
        assert not rebuilt['budget_exceeded'] and rebuilt['gate']['decision']=='proceed'
        context,messages=rebuilt['context'],rebuilt['messages']
        pair_attempts=[]; final_artifacts=None
        for attempt_index in (1,2):
            capture={};artifacts=deepcopy(base_artifacts);attempt_dir=directory/f'attempt_{attempt_index:02d}'
            attempt_dir.mkdir(exist_ok=False);PERSISTENCE_ERRORS.clear()

            class ObservedClient(p.LLMClient):
                def generate(self,supplied):
                    integrity()
                    reservation={'ordinal':len(attempts)+1,'question_id':row['case_id'],'branch':row['branch'],
                        'pair_attempt':attempt_index,'reserved_utc':utc(),'actual_http_attempts':None}
                    attempts.append(reservation);pair_attempts.append(reservation);checkpoint()
                    original_open=urllib.request.urlopen
                    def observed(request,*args,**kwargs):
                        payload=json.loads(request.data)
                        assert payload['thinking']=={'type':'disabled'} and payload['max_tokens']==16384
                        assert payload['model']==MODEL.model_name and payload['temperature']==MODEL.temperature
                        assert hashlib.sha256(p.canonical_bytes(payload['messages'])).hexdigest()==row['messages_sha256']
                        capture['actual_payload']={k:payload[k] for k in ('model','temperature','max_tokens','thinking','stream')}
                        capture['actual_payload'].update(messages_sha256=row['messages_sha256'],serialized_http_payload_bytes=len(request.data),endpoint=request.full_url)
                        started=time.perf_counter();capture['http_started_utc']=utc()
                        try:
                            try: response=original_open(request,*args,**kwargs)
                            except urllib.error.HTTPError as error:
                                data=error.read(65537);capture.update(http_status=error.code,retry_after=error.headers.get('Retry-After'))
                                try: body=json.loads(data[:65536])
                                except ValueError:body={'text':data[:65536].decode('utf-8',errors='replace')}
                                capture['sanitized_error_body']=safe(body)
                                write(attempt_dir/'provider_error_body.json',{'http_status':error.code,'body':safe(body),'truncated':len(data)>65536})
                                replacement=urllib.error.HTTPError(error.url,error.code,error.msg,error.headers,BytesIO(data));error.close();raise replacement from None
                            with response:data=response.read();headers=response.headers;status=response.status
                            capture['http_status']=status
                            try:
                                body=json.loads(data)
                                if isinstance(body,dict):
                                    capture['usage']=safe(body.get('usage'));capture['cost']=provider_cost(body)
                                    choices=body.get('choices') or []
                                    capture['finish_reason']=choices[0].get('finish_reason') if choices else None
                                    if body.get('error'):capture['sanitized_error_body']=safe(body['error'])
                                write(attempt_dir/'provider_response.json',safe(body))
                            except (ValueError,UnicodeDecodeError):
                                write(attempt_dir/'provider_non_json_response.json',{'text':safe(data.decode('utf-8',errors='replace'))})
                            result=BytesIO(data);result.headers=headers;result.status=status;return result
                        finally:
                            capture['http_seconds']=time.perf_counter()-started;capture['http_finished_utc']=utc()
                    try:
                        with patch('urllib.request.urlopen',side_effect=observed):return super().generate(supplied)
                    finally:
                        reservation.update(actual_http_attempts=self.last_attempt_count,finished_utc=utc(),**safe(capture))
                        snapshot(ledger_path,{'maximum_authorized':None,'attempts':attempts,'stopped_reason':stopped})
                        write(attempt_dir/'http_observation.json',safe(capture))

            print(json.dumps({'phase':'generation_queued','question_id':row['case_id'],'branch':row['branch'],'pair_attempt':attempt_index},ensure_ascii=True),flush=True)
            def emit(name,value):
                artifacts[name]=deepcopy(value);write(attempt_dir/(name+'.json'),value)
            generated,shared_stop=p.generate_branch(messages,context,MODEL,pacer.wrap(ObservedClient),emit)
            row.update(generated,provider_http_seconds=sum(a.get('http_seconds',0) for a in pair_attempts),provider_usage=capture.get('usage'),
                provider_reported_cost=capture.get('cost'),generation_started_utc=capture.get('http_started_utc'),
                generation_finished_utc=capture.get('http_finished_utc'),finish_reason=capture.get('finish_reason'),
                llm_http_attempts=sum(a.get('actual_http_attempts') or 0 for a in pair_attempts),http_status=capture.get('http_status'))
            row['config_run_id']=OUT.name;row['attempt_diagnostics']=[safe(a) for a in pair_attempts]
            if capture.get('finish_reason')=='length':
                row.update(outcome='truncated_response',validation_status='not_run');stopped='truncation_requires_payload_usage_diagnosis'
            if PERSISTENCE_ERRORS:
                row.update(outcome='persistence_error',persistence_errors=deepcopy(PERSISTENCE_ERRORS));stopped='persistence_error'
            snapshot(attempt_dir/'result.json',row);snapshot(directory/'result.json',row);checkpoint()
            error_text=json.dumps(capture.get('sanitized_error_body',{})).lower()
            fatal=capture.get('http_status') in (401,402,403) or any(t in error_text for t in ('insufficient_balance','insufficient balance','insufficient_quota','quota exceeded','billing_hard_limit'))
            if fatal:stopped='provider_auth_balance_or_quota_error'
            kind=(row.get('provider_error') or {}).get('kind','')
            transient=capture.get('http_status') in (429,503) or 'timeout' in kind
            if not stopped and transient and attempt_index==1:
                delay=(row.get('provider_error') or {}).get('retry_after_seconds') or 0
                try:delay=max(float(delay),float(capture.get('retry_after') or 0))
                except (ValueError,TypeError):pass
                deadline=time.monotonic()+delay
                print(json.dumps({'phase':'transient_retry_wait','question_id':row['case_id'],'branch':row['branch'],'retry_after_seconds':delay}),flush=True)
                while time.monotonic()<deadline:time.sleep(min(1,deadline-time.monotonic()))
                continue
            if not stopped and transient and attempt_index==2:stopped='persistent_provider_unavailability_after_one_retry'
            if row.get('provider_error') and not transient and not stopped:stopped='provider_protocol_error_requires_diagnosis'
            final_artifacts=artifacts;break
        artifacts=final_artifacts or artifacts
        metadata={'model':p._safe_config(MODEL),'profile_id':OUT.name,'artifacts':protocol['artifacts'],'source_configuration':CONFIG,
            'source_manifest_sha256':protocol['source_manifest_sha256'],'llm_http_attempts':row['llm_http_attempts'],'maximum_llm_requests':None}
        response=response_payload(ExperimentalRequest(query=row['query'],scenario_id=row['scenario_id'],branch=row['branch']),
            row,artifacts,metadata,{'mode':'paired_current_source_experiment','run_id':OUT.name,'directory':directory.relative_to(ROOT).as_posix(),'benchmark_result':True})
        raw_output=artifacts.get('raw_model_output',{}).get('text')
        response['generation_evidence']={'created_utc':row['generation_finished_utc'],'model_output_sha256':hashlib.sha256(raw_output.encode()).hexdigest() if isinstance(raw_output,str) else None,
            'new_llm_response':bool(row['llm_http_attempts'] and isinstance(raw_output,str)),'benchmark_result':True}
        response['source_receipts']={name:p._read(directory/(name+'_receipt.json')) for name in ('context','messages','evidence_contract')}
        response['context']={'source_ground_truth':context['source_ground_truth'],'persistence':'Exact context reconstructible from pinned sources and receipt hashes'}
        response['messages']=None;response['evidence_contract']=None
        write(directory/'response.json',response)
        report=response.get('report') or response.get('generation',{}).get('report') or {}
        write(directory/'citations.json',{'question_id':row['case_id'],'branch':row['branch'],'citations':report.get('citations',[]),
            'evidence':report.get('evidence',[]),'source_receipt':response['source_receipts']['evidence_contract']})
        row.update(response_path=(directory/'response.json').relative_to(ROOT).as_posix(),citations_path=(directory/'citations.json').relative_to(ROOT).as_posix())
        snapshot(directory/'result.json',row);checkpoint()
        print(json.dumps({'phase':'completed','question_id':row['case_id'],'branch':row['branch'],'outcome':row['outcome'],
            'finish_reason':row.get('finish_reason'),'usage':row.get('provider_usage'),'attempts':sum(a.get('actual_http_attempts') or 0 for a in attempts),'stop':stopped},ensure_ascii=True),flush=True)
    integrity()
    for item in protocol['raw_inputs']:assert p.sha256(ROOT/item['path'])==item['sha256']
    result=checkpoint()
    write(OUT/'finished.json',{'finished_utc':utc(),'http_attempts':result['http_attempts'],'stopped_reason':stopped,'frozen_config_code_data_unchanged':True})
    print(json.dumps({'phase':'finished','completed':result['completed_branches'],'attempts':result['http_attempts'],'by_branch':result['by_branch'],'stop':stopped}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=['prepare','live'])
    args=parser.parse_args()
    if args.phase=='prepare':prepare()
    else:live()


