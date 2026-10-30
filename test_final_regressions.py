"""Offline final-release regressions, without importing Streamlit UI or calling Gemini."""
import ast, json, sqlite3, tempfile, re, random, uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
source=Path(__file__).with_name('app.py').read_text()
tree=ast.parse(source)
names={'db','query','execsql','record','ensure_seed','reset_case','verify_state','tool_call','generate_cases','evaluation_metrics'}
body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
scenarios=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SCENARIOS' for t in n.targets)))
samples=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SAMPLES' for t in n.targets)))
seed=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SEED' for t in n.targets)))
with tempfile.TemporaryDirectory() as d:
    env=dict(sqlite3=sqlite3,Path=Path,DB=Path(d)/'test.db',datetime=datetime,timezone=timezone,json=json,re=re,urlparse=urlparse,random=random,uuid=uuid,SEVERITIES=('Critical','High','Medium','Low'),THREATS=('Credential harvesting','Business email compromise','Fake invoice','OAuth consent phishing','Mass phishing','Graymail','Impersonation','Malicious link','Other','None identified'),SEED=seed,SCENARIOS=scenarios,SAMPLES=samples)
    exec(compile(ast.Module(body=body,type_ignores=[]),'test','exec'),env)
    # Operational PH records remain after running isolated fixed benchmark cases.
    original=samples['Credential harvesting']
    env['reset_case'](original)
    assert env['query']('SELECT * FROM mailbox WHERE email_id=?',(original['id'],))
    cases=env['generate_cases'](4,'Fixed Benchmark')
    assert all(c['id'].startswith('EV-') and c['id'] != c['original_case_id'] for c in cases)
    env['reset_case'](cases[0])
    assert env['query']('SELECT * FROM mailbox WHERE email_id=?',(original['id'],))
    assert env['query']("SELECT DISTINCT source FROM mailbox WHERE email_id=?",(cases[0]['id'],))[0]['source']=='evaluation'
    assert env['query']("SELECT DISTINCT source FROM mailbox WHERE email_id=?",(original['id'],))[0]['source']=='operational'
    # API-failed cases must not be treated as incorrect predictions.
    failed=[dict(expected_severity='High',predicted_severity=None,outcome='Unsuccessful investigation',policy_compliant=0,invalid_actions=0,tool_count=0,duration_seconds=.3)]*4
    m=env['evaluation_metrics'](failed)
    assert m['accuracy'] is None and m['classified']==0 and m['coverage']==0
    assert m['tool_success_rate'] is None and m['success_rate']==0
    mixed=failed[:2]+[dict(failed[0],predicted_severity='High'),dict(failed[0],predicted_severity='Low')]
    m=env['evaluation_metrics'](mixed)
    assert m['accuracy']==.5 and m['classified']==2 and m['coverage']==.5
    print('PASS: benchmark isolation, source separation, zero-tool N/A, failed-case exclusion, coverage')
