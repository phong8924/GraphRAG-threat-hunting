"""Verify the distributed checkout and saved-result startup without network/LLM."""
from pathlib import Path
from unittest.mock import patch
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'scripts'),str(ROOT/'src')]


def main():
    import portable_saved_runtime as run
    verification=run.verify_all()
    from fastapi.testclient import TestClient
    from scripts.serve_saved_results import app
    with patch('threat_hunting.llm.client.LLMClient.generate',side_effect=AssertionError('LLM forbidden during verification')) as llm:
        with TestClient(app) as client:
            assert client.get('/').status_code==200
            assert client.get('/results').status_code==200
            config=client.get('/experimental-api/config').json()
            assert config['generation_disabled'] and config['maximum_llm_requests']==0
            for case in ('PS-DIRECT','AUTH-CTI','NET-DIRECT'):
                response=client.get('/experimental-api/saved',params={'case_id':case,'branch':'graphrag'})
                assert response.status_code==200,response.text[:150]
                payload=response.json()
                assert payload['outcome']=='accepted_draft' and payload['validation']['status']=='passed'
                assert payload['provenance']['new_api_calls_for_view']==0
                assert payload['report']['evidence_refs'] and payload['context']['traversal']['nodes']
            assert client.post('/experimental-api/hunt',json={}).status_code==409
        assert llm.call_count==0
    print(json.dumps({**verification,'startup_and_saved_three_scenarios':'passed','live_generation_not_executed':True,'new_llm_calls':0}))


if __name__=='__main__':main()
