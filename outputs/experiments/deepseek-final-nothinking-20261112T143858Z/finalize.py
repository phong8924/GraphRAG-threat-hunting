"""Verify and enrich the completed real run without any provider request."""
from __future__ import annotations
from collections import Counter
from datetime import datetime
from pathlib import Path
import csv
import hashlib
import json
import os
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import run_final as run
from threat_hunting.evaluation.final_experiment import snapshot


def main():
    run.integrity()
    finish=run.p._read(HERE/'finished.json')
    result=run.p._read(HERE/'results.json')
    protocol=run.p._read(HERE/'execution_manifest.json')
    ledger=run.p._read(HERE/'attempts.json')
    attempts=ledger['attempts'];rows=result['rows']
    for branch in result['by_branch'].values():
        for name in ('accepted_draft','validation_failed','abstain','truncated_response','provider_error','rate_limited','not_run','not_run_after_stop','runtime_error','persistence_error'):
            branch['outcomes'].setdefault(name,0)
    assert protocol['script_sha256']==run.p.sha256(HERE/'run_final.py')
    assert len(rows)==24 and len({(r['question_id'],r['branch']) for r in rows})==24
    assert sum(a['actual_http_attempts'] for a in attempts)==result['http_attempts']==finish['http_attempts']
    assert run.p._safe_config(run.MODEL)==protocol['model']
    catalog={};usage=Counter();reasoning_nonempty=[]
    for a in attempts:
        assert a['actual_payload']['thinking']=={'type':'disabled'}
        assert a['actual_payload']['max_tokens']==16384
        assert a['actual_payload']['model']=='deepseek-flash'
        for k,v in (a.get('usage')or{}).items():
            if isinstance(v,int) and not isinstance(v,bool):usage[k]+=v
    for row in rows:
        directory=HERE/(row['case_id']+'_'+row['branch'])
        row['config_run_id']=HERE.name
        row['source_config']=protocol['source_config']
        row['source_manifest']=protocol['source_manifest']
        row['source_references_path']=(directory/'evidence_contract_receipt.json').relative_to(run.ROOT).as_posix()
        row['gate_receipt_path']=(directory/'gate_receipt.json').relative_to(run.ROOT).as_posix()
        row['eligibility_receipt_path']=(directory/'eligibility_receipt.json').relative_to(run.ROOT).as_posix()
        if row['outcome']=='abstain':
            assert row['llm_http_attempts']==0 and row['eligibility_decision']=='abstain'
            snapshot(directory/'result.json',row)
            continue
        response_path=directory/'response.json'
        if not response_path.exists():continue
        response=run.p._read(response_path)
        report=response.get('report')
        effective=directory/f"attempt_{len(row['attempt_diagnostics']):02d}"
        validation=response.get('validation')
        if row['outcome']=='accepted_draft':
            assert row['finish_reason']=='stop' and validation['status']=='passed' and report
            assert row['outcome']==response['outcome']
            catalog[directory.name]=run.p.sha256(response_path)
            text=run.p._read(effective/'raw_model_output.json')['text']
            assert hashlib.sha256(text.encode()).hexdigest()==response['generation_evidence']['model_output_sha256']
        raw_path=effective/'raw_report_before_sanitize.json'
        raw=run.p._read(raw_path) if raw_path.exists() else {}
        provider_path=effective/'provider_response.json'
        if provider_path.exists():
            provider=run.p._read(provider_path)
            for choice in provider.get('choices',[]):
                if choice.get('message',{}).get('reasoning_content'):reasoning_nonempty.append(directory.name)
        citations={'schema_version':'saved-report-citations/v1','question_id':row['question_id'],'scenario_id':row['scenario_id'],
            'branch':row['branch'],'config_run_id':HERE.name,'outcome':row['outcome'],
            'report_field':'evidence_refs','evidence_refs':(report or raw).get('evidence_refs',[]),
            'reference_checks':(validation or {}).get('reference_checks'),
            'source_evidence_receipt':run.p._read(directory/'evidence_contract_receipt.json'),
            'binding':'Exact references from the real report; validation checks preserved. No invented citation or human semantic approval.'}
        snapshot(directory/'citations_resolved.json',citations)
        row.update(response_path=response_path.relative_to(run.ROOT).as_posix(),
            citations_path=(directory/'citations_resolved.json').relative_to(run.ROOT).as_posix(),
            validation_path=(effective/('validation.json' if (effective/'validation.json').exists() else 'validation_failure.json')).relative_to(run.ROOT).as_posix(),
            provider_response_path=provider_path.relative_to(run.ROOT).as_posix())
        snapshot(directory/'result.json',row)
    gaps=[]
    for previous,current in zip(attempts,attempts[1:]):
        if previous.get('http_finished_utc') and current.get('http_started_utc'):
            gaps.append((datetime.fromisoformat(current['http_started_utc'])-datetime.fromisoformat(previous['http_finished_utc'])).total_seconds())
    assert not gaps or min(gaps)>=run.INTERVAL-0.02
    for item in protocol['raw_inputs']:assert run.p.sha256(run.ROOT/item['path'])==item['sha256']
    for path in HERE.rglob('*'):
        if path.is_file() and run.MODEL.api_key and run.MODEL.api_key.encode() in path.read_bytes():
            raise ValueError('Credential present in output; do not publish')
    old=run.ROOT/'outputs/demo/deepseek_live_20261112_v1/mshta_graphrag_response.json'
    assert run.p.sha256(old)=='133da7314ea577a1e1a7b5695e5762a889fbcddc0f51fea5118f83b1afb7a84f'
    result.update(token_usage=dict(usage),minimum_measured_http_gap_seconds=min(gaps) if gaps else None,
        execution_manifest_path=(HERE/'execution_manifest.json').relative_to(run.ROOT).as_posix(),
        source_manifest_sha256=protocol['source_manifest_sha256'],
        confirmed_monetary_cost=None,cost_status='Unknown: provider returned token usage but no monetary cost. Not zero.',
        reasoning_content_nonempty_responses=reasoning_nonempty)
    snapshot(HERE/'results.json',result)
    fields=('question_id','scenario_id','branch','config_run_id','outcome','gate_decision','eligibility_decision','abstention_stage','abstention_reason_codes',
        'context_utf8_bytes','messages_utf8_bytes','context_sha256','messages_sha256','llm_http_attempts','http_status','finish_reason','validation_status',
        'provider_http_seconds','generation_validation_seconds','provider_usage','provider_reported_cost','provider_error','response_path','citations_path','source_references_path')
    with (HERE/'results.csv.tmp').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');writer.writeheader()
        for row in rows:writer.writerow({k:json.dumps(row.get(k),ensure_ascii=False) if isinstance(row.get(k),(dict,list)) else row.get(k) for k in fields})
    os.replace(HERE/'results.csv.tmp',HERE/'results.csv')
    assert len(list(csv.DictReader((HERE/'results.csv').open(encoding='utf-8-sig',newline=''))))==24
    snapshot(HERE/'saved_catalog.json',{'schema_version':'real-paired-saved-catalog/v1','run_id':HERE.name,'response_sha256':catalog,
        'results_sha256':run.p.sha256(HERE/'results.json'),'source_manifest_sha256':protocol['source_manifest_sha256'],
        'viewer_script_sha256':run.p.sha256(HERE/'view_results.py'),'new_api_calls_for_view':0})
    snapshot(HERE/'closeout_verification.json',{'verified_utc':run.utc(),'rows':24,'http_attempts':result['http_attempts'],
        'raw_inputs_hash_verified':len(protocol['raw_inputs']),'current_source_manifest_verified':True,
        'same_actual_payload_configuration_every_attempt':True,'minimum_http_gap_seconds':min(gaps) if gaps else None,
        'original_accepted_mshta_hash_unchanged':True,'output_api_key_scan':'absent','actual_reasoning_content_nonempty':reasoning_nonempty,
        'source_gate_validator_unchanged_during_run':True,'full_suite_run':False,'monetary_cost':'unknown',
        'focused_test_command':'.venv/Scripts/python.exe -B -m pytest tests/test_llm_client.py -q','focused_tests_observed_passed':60})
    extra=['','## Verified closeout','',f"Actual usage: {dict(usage)}.",f"Minimum measured gap: {min(gaps) if gaps else None} seconds.",
        'All 10 original inputs, current code/config/frontend manifest, source consumers and original accepted MSHTA were verified unchanged during this run.',
        'Citations use the actual report schema field evidence_refs; citations_resolved.json preserves those references and validator reference_checks.',
        'No Word edits, full suite, UI redesign, model switch, fallback, or fabricated response.',
        'Evidence gate: 17 proceed / 7 abstain; context budget: 2 additional abstain; final eligibility: 15 proceed / 9 abstain.',
        'Only AUTH-CTI, PS-CORRELATE, NET-CORRELATE and NET-LIMIT have both branches eligible. Eligibility differences must remain visible in any paired comparison.',
        '', '| Branch | accepted_draft | validation_failed | abstain | truncated | provider_error | not_run | HTTP |',
        '|---|---:|---:|---:|---:|---:|---:|---:|',
        *[f"|{b}|{v['outcomes']['accepted_draft']}|{v['outcomes']['validation_failed']}|{v['outcomes']['abstain']}|{v['outcomes']['truncated_response']}|{v['outcomes']['provider_error']+v['outcomes']['rate_limited']}|{v['outcomes']['not_run']+v['outcomes']['not_run_after_stop']}|{v['http_attempts']}|" for b,v in result['by_branch'].items()],
        '', '## Dashboard / screenshots', '', 'Launcher: START_RESULTS_DEEPSEEK.cmd. Catalog: http://127.0.0.1:8034/results .',
        'Direct saved views (0 new API calls):']
    preferred=[]
    for sid in ('mshta-powershell','purplesharp-ad','regsvr32-c2'):
        selected=next((r for r in rows if r['scenario_id']==sid and r['branch']=='graphrag' and r['outcome']=='accepted_draft'),None)
        if selected:
            link=f"http://127.0.0.1:8034/view/{selected['case_id']}/{selected['branch']}"
            preferred.append({'scenario_id':sid,'question_id':selected['case_id'],'branch':selected['branch'],'url':link,
                'response_path':selected['response_path'],'citations_path':selected['citations_path']})
            extra.append('- '+sid+': '+link)
    extra += ['','Browser control was blocked because the current URL could not be determined confidently. No new screenshot or visual UI acceptance is claimed.',
        'Open one direct saved URL, wait for accepted_draft and the saved-result/0 API calls label, collapse metadata if needed, then capture the answer, source cards and limits. Existing dividers remain available.',
        'accepted_draft is not semantic accuracy. Abstentions and draft answers still require separate evidence/citation review before thesis claims.']
    with (HERE/'report.md').open('a',encoding='utf-8') as f:f.write('\n'.join(extra)+'\n')
    snapshot(HERE/'preferred_saved_views.json',{'new_api_calls_for_view':0,'results':preferred})
    print(json.dumps({'completed':result['completed_branches'],'http_attempts':result['http_attempts'],'by_branch':result['by_branch'],
        'usage':dict(usage),'preferred_saved_views':preferred,'confirmed_monetary_cost':None},ensure_ascii=True))


if __name__=='__main__':main()
