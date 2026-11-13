"""Current-profile integrity, UI transport and request controls; explicitly synthetic fixtures only."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import json

from fastapi.testclient import TestClient
import pytest

from scripts import current_interactive_runtime as current
from scripts import interactive_runtime as base


@pytest.fixture
def bound_manifest(tmp_path, monkeypatch):
    config={'schema_version':'experimental-comparison-config/v2','runtime_mode':'interactive_per_question',
        'profile_id':'SYNTHETIC-current','branches':['rag','graphrag'],'maximum_llm_requests':2,
        'gate_contract':'source-evidence-contract/v2','generation_contract':'source-meaning/v3',
        'benchmark':'cases.json','gate_policy':'gate.json','runtime_artifacts':'registry.json'}
    manifest={'schema_version':current.SCHEMA,'purpose':'interactive_current_source','profile_id':config['profile_id'],
        'benchmark_certified':False,'generation_preflight_certified':False,'config_sha256':'hash',
        'code_sha256':{'source.py':'hash'},'adapter_sha256':{'adapter.py':'hash'},'frontend_sha256':{'ui.js':'hash'},
        'cases_sha256':'hash','gate_policy_sha256':'hash','runtime_artifacts_config_sha256':'hash',
        'dependency_spec_sha256':'hash','environment':{'synthetic-package':'1'},'artifacts':{'synthetic':'bound'},
        'model':{'synthetic-model':'single-attempt'},'generation_contract':'source-meaning/v3'}
    monkeypatch.setattr(current.p,'_read',lambda path:config if path.name=='config.json' else manifest)
    monkeypatch.setattr(current.p,'sha256',lambda path:'hash')
    monkeypatch.setattr(current.p,'_code_manifest',lambda:{'source.py':'hash'})
    monkeypatch.setattr(current,'adapter_hashes',lambda:{'adapter.py':'hash'})
    monkeypatch.setattr(base,'frontend_hashes',lambda:{'ui.js':'hash'})
    monkeypatch.setattr(current,'environment_versions',lambda:{'synthetic-package':'1'})
    monkeypatch.setattr(current.p,'_runtime_sources',lambda path:{'synthetic':'paths'})
    monkeypatch.setattr(current.p,'_source_manifest',lambda paths:{'synthetic':'bound'})
    monkeypatch.setattr(base,'validate_consumers',Mock())
    from threat_hunting.llm.config import LLMConfig
    monkeypatch.setattr(current.p.LLMConfig,'from_env',classmethod(lambda cls:LLMConfig(model_name='SYNTHETIC',max_retries=5)))
    def safe_config(config):
        assert config.max_retries==1
        return {'synthetic-model':'single-attempt'}
    monkeypatch.setattr(current.p,'_safe_config',safe_config)
    return config,manifest,tmp_path/'config.json',tmp_path/'manifest.json'


def test_new_profile_verifies_all_current_bindings_without_mutating_history(bound_manifest):
    config,manifest,cpath,mpath=bound_manifest
    before=deepcopy(manifest)
    assert current.verify_current_manifest(cpath,mpath)==manifest
    assert manifest==before
    base.validate_consumers.assert_called_once_with({'synthetic':'paths'})


@pytest.mark.parametrize('field',['config_sha256','code_sha256','adapter_sha256','frontend_sha256','cases_sha256',
    'gate_policy_sha256','runtime_artifacts_config_sha256','dependency_spec_sha256','environment','artifacts','model','generation_contract'])
def test_every_current_manifest_binding_rejects_tampering(bound_manifest,field):
    _,manifest,cpath,mpath=bound_manifest
    manifest[field]='SYNTHETIC-TAMPERED'
    with pytest.raises(ValueError):current.verify_current_manifest(cpath,mpath)


@pytest.mark.parametrize('field,value',[('maximum_llm_requests',7),('gate_contract','none'),('generation_contract','none'),
    ('runtime_mode','legacy'),('branches',['graphrag']),('final_run_policy',{})])
def test_current_config_cannot_expand_budget_or_weaken_pipeline(bound_manifest,field,value):
    config,_,cpath,mpath=bound_manifest
    config[field]=value
    with pytest.raises(ValueError):current.verify_current_manifest(cpath,mpath)


def test_dashboard_budget_six_keeps_probe_plus_scenarios_within_seven(bound_manifest):
    config,manifest,cpath,mpath=bound_manifest
    config['maximum_llm_requests']=6
    assert current.verify_current_manifest(cpath,mpath)==manifest


def test_v2_dispatches_to_full_verifier(bound_manifest):
    _,manifest,cpath,mpath=bound_manifest
    assert base.verify_manifest(cpath,mpath)==manifest


def test_reading_current_session_results_never_generates(monkeypatch):
    from threading import Lock
    request={'query':'SYNTHETIC query','scenario_id':'mshta-powershell','branch':'rag'}
    stored={'request':request,'outcome':'accepted_draft','report':{'direct_answer':'SYNTHETIC fixture'},
        'configuration':{},'provenance':{'mode':'interactive_per_question'},'result':{'llm_http_attempts':1}}
    session=SimpleNamespace(config={'profile_id':'synthetic'},lock=Lock(),recent_results=[stored],
        metadata=lambda:{'maximum_llm_requests':2},presets=lambda:[],run=Mock(side_effect=AssertionError('No generation from GET')))
    with TestClient(current.create_current_app(session)) as client:
        value=client.get('/experimental-api/recent?branch=rag').json()
        assert value['report']['direct_answer']=='SYNTHETIC fixture'
        assert 'zero_new_calls' in value['provenance']['display_source']
        assert client.get('/experimental-api/recent?branch=graphrag').json() is None
        assert client.get('/experimental-api/saved').status_code==409
        assert client.get('/experimental-api/config?profile=wrong').status_code==422
    session.run.assert_not_called()
    assert stored['provenance']=={'mode':'interactive_per_question'}


def test_persistence_error_http507_suppresses_success(monkeypatch):
    session=SimpleNamespace(config={'profile_id':'synthetic'},run=lambda req:{'outcome':'persistence_error','report':None},
        metadata=lambda:{},presets=lambda:[])
    with TestClient(current.create_current_app(session)) as client:
        response=client.post('/experimental-api/hunt',json={'query':'SYNTHETIC','scenario_id':'mshta-powershell','branch':'rag'})
        assert response.status_code==507 and response.json()['report'] is None


def test_mshta_binding_uses_exact_aligned_refs_and_preserves_labels():
    from scripts.build_current_live_consumers import bind_mshta_observations
    document={'facts':[{'status':'observed','source_references':[{'source_file':'SYNTHETIC.jsonl','raw_record_ref':ref}],
        'attributes':{},'evidence_ids':[ref]} for ref in ('jsonl:line:1','jsonl:line:2')],
        'review':{'review_status':'pending_human_review'},'mitre_assessments':[{'status':'candidate'}]}
    rows=[{'source_file':'SYNTHETIC.jsonl','raw_record_ref':ref,'original_fields':{'TimeCreated':'2020-01-01T00:00:00Z'},
        'canonical_fields':{'event_id':'1','process_name':child,'parent_process_name':parent}}
        for ref,parent,child in (('jsonl:line:1','cmd.exe','mshta.exe'),('jsonl:line:2','mshta.exe','powershell.exe'))]
    before=deepcopy(document)
    bound=bind_mshta_observations(document,rows)
    assert document==before and bound['review']==before['review'] and bound['mitre_assessments']==before['mitre_assessments']
    assert bound['facts'][0]['attributes']['source_observations'][0]['canonical_fields']['process_name']=='mshta.exe'
    with pytest.raises(ValueError,match='does not resolve'):bind_mshta_observations(document,rows[:1])
    rows[0]['canonical_fields']['event_id']='3'
    with pytest.raises(ValueError,match='creation record'):bind_mshta_observations(document,rows)
