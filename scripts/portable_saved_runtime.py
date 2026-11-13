"""Key-free replay bindings for the distributed saved study; no generation code.

The historical pin and every core/consumer/build hash remain unchanged. Live
continues to use the original strict current_interactive_runtime verifier.
"""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys
import hashlib
import os

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'outputs/experiments/deepseek-final-nothinking-20261112T143858Z'
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
for variable in ('HF_HUB_OFFLINE','TRANSFORMERS_OFFLINE','HF_HUB_DISABLE_TELEMETRY','HF_HUB_DISABLE_IMPLICIT_TOKEN'):
    os.environ[variable]='1'
from threat_hunting.evaluation import experimental_comparison as p
from scripts import interactive_runtime as base
from scripts.current_interactive_runtime import adapter_hashes,environment_versions,SCHEMA

CONFIG_PATH=ROOT/'configs/interactive/dashboard_live_v10.json'
PIN_PATH=ROOT/'configs/interactive/runtime_manifest_live_v9.json'
CONFIG=p._read(CONFIG_PATH)
PIN=p._read(PIN_PATH)
PROTOCOL=p._read(OUT/'execution_manifest.json')
RAW_CASES=p._read(ROOT/CONFIG['benchmark'])
CASES=RAW_CASES['cases']
PATHS=p._runtime_sources(ROOT/CONFIG['runtime_artifacts'])
settings=PROTOCOL['model']
MODEL=p.LLMConfig(provider=settings['provider'],model_name=settings['model_name'],base_url=settings['base_url'],
    api_key='',temperature=settings['temperature'],max_tokens=settings['max_tokens'],timeout_seconds=settings['timeout_seconds'],
    max_retries=1,thinking=settings.get('thinking',{}).get('type'))


def integrity():
    """Verify original static replay bindings, without requiring a private key."""
    if PIN.get('schema_version')!=SCHEMA or PIN.get('purpose')!='interactive_current_source':
        raise ValueError('Unexpected source manifest')
    if PIN.get('benchmark_certified') is not False or PIN.get('generation_preflight_certified') is not False:
        raise ValueError('Do not promote source manifest certification')
    if CONFIG['profile_id']!=PIN['profile_id'] or p.sha256(CONFIG_PATH)!=PIN['config_sha256']:
        raise ValueError('Replay configuration hash mismatch')
    if p.sha256(PIN_PATH)!=PROTOCOL['source_manifest_sha256'] or p.sha256(CONFIG_PATH)!=PROTOCOL['source_config_sha256']:
        raise ValueError('Study/source manifest binding mismatch')
    if p._code_manifest()!=PIN['code_sha256'] or adapter_hashes()!=PIN['adapter_sha256']:
        raise ValueError('Replay core/adapter hash inventory mismatch')
    if base.frontend_hashes()!=PIN['frontend_sha256']:
        raise ValueError('Replay frontend source/build mismatch')
    for field,key in (('benchmark','cases_sha256'),('gate_policy','gate_policy_sha256'),('runtime_artifacts','runtime_artifacts_config_sha256')):
        if p.sha256(ROOT/CONFIG[field])!=PIN[key]:raise ValueError('Replay binding mismatch: '+field)
    if p.sha256(ROOT/'pyproject.toml')!=PIN['dependency_spec_sha256'] or environment_versions()!=PIN['environment']:
        raise ValueError('Replay dependency environment changed; install requirements.lock')
    if p._source_manifest(p._runtime_sources(ROOT/CONFIG['runtime_artifacts']))!=PIN['artifacts']:
        raise ValueError('Replay consumer integrity mismatch')
    if p._safe_config(MODEL)!=PIN['model'] or PIN['model']!=PROTOCOL['model']:
        raise ValueError('Saved generation/validator settings mismatch')
    if CONFIG['generation_contract']!=PIN['generation_contract']:
        raise ValueError('Replay generation contract mismatch')
    catalog=p._read(OUT/'saved_catalog.json')
    if p.sha256(OUT/'results.json')!=catalog['results_sha256']:
        raise ValueError('Saved results/catalog integrity mismatch')
    if p.sha256(OUT/'view_results.py')!=catalog['viewer_script_sha256']:
        raise ValueError('Historical viewer source changed')


def verify_all():
    integrity()
    base.validate_consumers(PATHS)
    for item in p._read(ROOT/'packaging/inputs.json')['inputs']:
        path=ROOT/item['path']
        if not path.is_file() or path.stat().st_size!=item['size_bytes'] or p.sha256(path)!=item['sha256']:
            raise ValueError('Original data hash/size mismatch: '+item['filename'])
    catalog=p._read(OUT/'saved_catalog.json')
    for key,expected in catalog['response_sha256'].items():
        if p.sha256(OUT/key/'response.json')!=expected:raise ValueError('Saved response changed: '+key)
    return {'core_build_consumers_data_results_integrity':'passed','saved_accepted_responses':len(catalog['response_sha256']),'llm_calls':0}


def utc():return datetime.now(timezone.utc).isoformat()

# The exact rebuild() function from the immutable run_final.py is appended by
# the distribution builder. No retrieval, evidence gate or validator changes.

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
