"""Read-only adapter for actual saved paired-run results, using unchanged frontend.

No generation endpoint exists. Exact inputs are rebuilt and hash-checked in RAM.
"""
from __future__ import annotations
from copy import deepcopy
from functools import lru_cache
from html import escape
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'scripts'),str(ROOT/'src')]
import portable_saved_runtime as run
HERE=run.OUT
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

ROOT=run.ROOT
app=FastAPI(title='Saved DeepSeek paired results - no generation',docs_url=None,redoc_url=None)
BACKENDS={}


def results():
    run.integrity()
    return run.p._read(HERE/'results.json')


def rows():
    return results()['rows']


def accepted():
    return [r for r in rows() if r['outcome']=='accepted_draft']


def metadata():
    protocol=run.p._read(HERE/'execution_manifest.json')
    return {'mode':'historical_replay_only','runtime_mode':'interactive_per_question','generation_disabled':True,
        'maximum_llm_requests':0,'llm_http_attempts':0,'stopped_reason':None,
        'current_source_profile':True,'load_latest_on_open':True,
        'profile_id':HERE.name+'-saved-view','source_profile_id':run.CONFIG['profile_id'],
        'model':protocol['model'],'artifacts':protocol['artifacts'],'generation_contract':run.CONFIG['generation_contract'],
        'validator_policy_id':run.CONFIG['validator_policy_id'],'saved_replay_available':True,'legacy_available':False,
        'release_limitation':'Read-only actual saved results. 0 new API calls. accepted_draft requires human semantic/citation review.',
        'presets':[{'case_id':c['case_id'],'scenario_id':c['scenario_id'],'query':c['request']['query']} for c in run.CASES],
        'artifact_profiles':[{'profile_id':HERE.name+'-saved-view','label':'Saved DeepSeek 12x2 - 0 API calls'}]}


@lru_cache(maxsize=24)
def load(case_id,branch,response_hash):
    matching=[r for r in rows() if r['case_id']==case_id and r['branch']==branch]
    if not matching:raise HTTPException(404,'Unknown case/branch')
    row=matching[0]
    if row['outcome']!='accepted_draft':raise HTTPException(409,'This result is not accepted_draft; original validation is preserved')
    path=HERE/(case_id+'_'+branch)/'response.json'
    if run.p.sha256(path)!=response_hash:raise HTTPException(409,'Saved response hash changed')
    original=run.p._read(path)
    if original['outcome']!='accepted_draft' or original.get('validation',{}).get('status')!='passed':
        raise HTTPException(409,'Stored accepted/validation binding is inconsistent')
    prepared,artifacts=run.rebuild(row,BACKENDS)
    response=deepcopy(original)
    response.update(context=prepared['context'],messages=artifacts['messages'],evidence_contract=artifacts.get('evidence_contract'),
        display_origin='saved',display_compact=True,configuration=metadata())
    response['provenance']={**original['provenance'],'mode':'saved_experimental_replay','source_execution_mode':original['provenance']['mode'],
        'source_generation_profile':HERE.name,'historical_validator_policy':{'policy_id':run.CONFIG['validator_policy_id']},
        'historical_llm_http_attempts':row['llm_http_attempts'],'llm_http_attempts':0,
        'source_response_sha256':response_hash,'new_api_calls_for_view':0,'source_runtime_manifest':run.PIN_PATH.relative_to(ROOT).as_posix()}
    # Keep the actual original generation timestamp, report, validation and attempt count.
    return response


def saved(case_id,branch):
    path=HERE/(case_id+'_'+branch)/'response.json'
    if not path.is_file():raise HTTPException(404,'No saved response for this pair')
    catalog_path=HERE/'saved_catalog.json'
    if catalog_path.exists():
        catalog=run.p._read(catalog_path)
        expected=catalog['response_sha256'].get(case_id+'_'+branch)
        if not expected or run.p.sha256(path)!=expected:raise HTTPException(409,'Saved response/catalog integrity mismatch')
    else:expected=run.p.sha256(path)
    return load(case_id,branch,expected)


@app.get('/experimental-api/config')
def config():return metadata()


@app.get('/experimental-api/recent')
def recent(request:Request):
    available=accepted()
    if not available:return None
    choice=request.cookies.get('saved_study_case','')
    selected=next((r for r in available if r['case_id']+'_'+r['branch']==choice),None)
    if selected is None:
        selected=next((r for r in available if r['scenario_id']=='mshta-powershell' and r['branch']=='graphrag'),available[0])
    return saved(selected['case_id'],selected['branch'])


@app.get('/experimental-api/saved')
def saved_api(case_id:str,branch:str):return saved(case_id,branch)


@app.post('/experimental-api/hunt')
def hunt():raise HTTPException(409,'Saved-result viewer: generation disabled; 0 new API calls. Select a saved result at /results')


@app.get('/view/{case_id}/{branch}')
def select(case_id:str,branch:str):
    if not any(r['case_id']==case_id and r['branch']==branch for r in accepted()):
        raise HTTPException(409,'No accepted saved result for this selection')
    response=RedirectResponse('/?saved='+case_id+'&branch='+branch,status_code=303)
    response.set_cookie('saved_study_case',case_id+'_'+branch,httponly=True,samesite='strict')
    return response


@app.get('/results',response_class=HTMLResponse)
def index():
    result=results()
    links=''.join('<li><a href="/view/'+escape(r['case_id'])+'/'+r['branch']+'">'+escape(r['case_id']+' / '+r['branch']+' / '+r['scenario_id'])+'</a></li>' for r in accepted())
    return '<!doctype html><meta charset="utf-8"><title>Saved DeepSeek results</title><h1>Saved DeepSeek results · 0 API calls</h1><p>'+str(result['completed_branches'])+'/24 completed; '+str(result['http_attempts'])+' original HTTP attempts. accepted_draft requires human review.</p><ul>'+links+'</ul><p><a href="/study/results.json">Results JSON</a> · <a href="/study/results.csv">CSV</a> · <a href="/study/report.md">Report</a></p>'


@app.get('/study/{name}')
def summary(name:str):
    from fastapi.responses import FileResponse
    if name not in {'results.json','results.csv','report.md','saved_catalog.json'}:raise HTTPException(404)
    return FileResponse(HERE/name)


app.mount('/',StaticFiles(directory=ROOT/'frontend/dist',html=True),name='unchanged-current-frontend')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8034);args=parser.parse_args()
    run.integrity()
    import uvicorn
    uvicorn.run(app,host='127.0.0.1',port=args.port,log_level='info')
