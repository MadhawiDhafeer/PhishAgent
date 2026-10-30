"""Offline regression tests. No Gemini API calls required."""
import ast, json, sqlite3, tempfile, re, random, uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
source = Path(__file__).with_name('app.py').read_text()
tree = ast.parse(source)
names = {'db','query','execsql','record','ensure_seed','reset_case','verify_state','tool_call','generate_cases','evaluation_metrics'}
body = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
with tempfile.TemporaryDirectory() as d:
    env = dict(sqlite3=sqlite3,Path=Path,DB=Path(d)/'test.db',datetime=datetime,timezone=timezone,json=json,re=re,urlparse=urlparse,random=random,uuid=uuid,
               SEVERITIES=('Critical','High','Medium','Low'),
               THREATS=('Credential harvesting','Business email compromise','Fake invoice','OAuth consent phishing','Mass phishing','Graymail','Impersonation','Malicious link','Other','None identified'),
               SEED={},SCENARIOS=[('Executive transfer impersonation','Critical','Critical','executive','CEO requests unauthorized wire transfer.'),('Routine HR update','Low','Low','internal','Office hours are updated.')],SAMPLES={})
    exec(compile(ast.Module(body=body,type_ignores=[]),'test','exec'),env)
    def incident(email, severity, ignored='Low', threat='None identified'):
        env['reset_case'](email)
        env['tool_call']('inspect_email',email,{})
        env['tool_call']('audit_exposure',email,{})
        return env['tool_call']('create_incident',email,dict(risk_level=severity,threat_type=threat,attack_technique='Observed content and sender context',reason='This is an evidence-led assessment based on the observed message indicators.',evidence='The sender, body content, destination domains and simulated employee exposure were examined.'))
    def mail(eid, clicked=1):
        return dict(id=eid,sender='alerts@outside.example',subject='Please review',body='Please review https://outside.example/verify',legitimate_domain='company.example',recipients=[('a@company.example',clicked)])
    critical=mail('CRIT')
    assert not incident(critical,'Critical',threat='Business email compromise').get('error')
    assert not env['verify_state']('CRIT')['verified']
    assert not env['tool_call']('recommend_identity_response',critical,{}).get('error')
    env['tool_call']('quarantine_simulated',critical,{})
    env['tool_call']('notify_soc',critical,{})
    env['tool_call']('create_training',critical,{'tip':'Verify urgent requests using trusted company channels. Never disclose your password through an unsolicited link.'})
    assert env['verify_state']('CRIT')['verified']
    medium=mail('MED')
    assert not incident(medium,'Medium',threat='Mass phishing').get('error')
    assert env['tool_call']('quarantine_simulated',medium,{}).get('error')
    assert not env['tool_call']('route_mail_simulated',medium,{}).get('error')
    assert env['verify_state']('MED')['verified']
    low=mail('LOW',0)
    assert not incident(low,'Low',threat='Graymail').get('error')
    assert not env['tool_call']('route_mail_simulated',low,{}).get('error')
    assert env['verify_state']('LOW')['verified']
    benign=mail('BEN',0)
    assert not incident(benign,'Low').get('error')
    assert env['tool_call']('notify_soc',benign,{}).get('error')
    env['tool_call']('route_mail_simulated',benign,{})
    assert env['verify_state']('BEN')['verified']
    review=mail('REV',0)
    assert not incident(review,'Low').get('error')
    assert env['tool_call']('notify_soc',review,{}).get('error')
    assert env['tool_call']('quarantine_simulated',review,{}).get('error')
    env['tool_call']('route_mail_simulated',review,{})
    assert env['verify_state']('REV')['verified']
    cases1=env['generate_cases'](10,'Dynamic Evaluation',42)
    cases2=env['generate_cases'](10,'Dynamic Evaluation',42)
    assert len(cases1)==10 and [c['scenario'] for c in cases1]==[c['scenario'] for c in cases2]
    assert len({c['id'] for c in cases1})==10
    env['execsql']('INSERT INTO evaluation_batches(id,mode,case_count,started_at) VALUES(?,?,?,?)',('B-1','Dynamic Evaluation',10,'now'))
    env['execsql']('INSERT INTO evaluation_cases(batch_id,case_id,scenario,email_json,expected_verdict,expected_severity,predicted_verdict,predicted_severity,outcome,duration_seconds,tool_count,invalid_actions,policy_compliant,trace_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('B-1','C-1','test','{}','High','High','High','High','Successful investigation',1.2,7,0,1,'[]','now'))
    rows=env['query']('SELECT * FROM evaluation_cases')
    assert env['evaluation_metrics'](rows)['accuracy']==1
    print('PASS: Critical, High-policy prerequisites, Medium archive, Low junk, benign, review, dynamic generation, evaluation persistence and metrics')
