"""Offline tests for policy safety, evaluation modes, and persistence."""
import ast, json, sqlite3, tempfile, re, random, uuid
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
source = Path(__file__).with_name('app.py').read_text()
tree = ast.parse(source)
names = {'db','query','execsql','record','ensure_seed','reset_case','verify_state','tool_call','generate_cases','evaluation_metrics'}
body = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
scenarios = ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SCENARIOS' for t in n.targets)))
samples = ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SAMPLES' for t in n.targets)))
with tempfile.TemporaryDirectory() as d:
    env = dict(sqlite3=sqlite3,Path=Path,DB=Path(d)/'test.db',datetime=datetime,timezone=timezone,json=json,re=re,urlparse=urlparse,random=random,uuid=uuid,
               SEVERITIES=('Critical','High','Medium','Low'),THREATS=('Credential harvesting','Business email compromise','Fake invoice','OAuth consent phishing','Mass phishing','Graymail','Impersonation','Malicious link','Other','None identified'),SEED={},SCENARIOS=scenarios,SAMPLES=samples)
    exec(compile(ast.Module(body=body,type_ignores=[]),'test','exec'),env)
    def mail(eid, clicked=0):
        return dict(id=eid,sender='alerts@outside.example',subject='Please review',body='Please review https://outside.example/verify',legitimate_domain='company.example',recipients=[('a@company.example',clicked)])
    def incident(email, severity, threat='None identified'):
        env['reset_case'](email)
        env['tool_call']('inspect_email',email,{})
        env['tool_call']('audit_exposure',email,{})
        return env['tool_call']('create_incident',email,dict(risk_level=severity,threat_type=threat,attack_technique='Observed content and sender context',reason='This is an evidence-led assessment based on observed message indicators.',evidence='The sender, body content, destination domains and simulated employee exposure were examined.'))
    critical=mail('CRIT',1)
    assert not incident(critical,'Critical','Business email compromise').get('error')
    assert not env['verify_state']('CRIT')['verified']
    env['tool_call']('recommend_identity_response',critical,{})
    env['tool_call']('quarantine_simulated',critical,{})
    env['tool_call']('notify_soc',critical,{})
    env['tool_call']('create_training',critical,{'tip':'Verify urgent requests using trusted company channels. Never disclose your password through an unsolicited link.'})
    assert env['verify_state']('CRIT')['verified']
    medium=mail('MED')
    incident(medium,'Medium','Mass phishing')
    assert env['tool_call']('quarantine_simulated',medium,{}).get('error')
    assert not env['tool_call']('route_mail_simulated',medium,{}).get('error')
    assert env['verify_state']('MED')['verified']
    low=mail('LOW')
    incident(low,'Low')
    assert env['tool_call']('route_mail_simulated',low,{}).get('error')
    assert env['verify_state']('LOW')['verified']
    assert env['query']('SELECT status FROM mailbox WHERE email_id=?',('LOW',))[0]['status']=='Delivered'
    assert env['tool_call']('notify_soc',low,{}).get('error')
    assert env['tool_call']('quarantine_simulated',low,{}).get('error')
    fixed=env['generate_cases'](4,'Fixed Benchmark')
    assert len(fixed)==4 and all(c['expected_severity'] in env['SEVERITIES'] for c in fixed)
    dynamic=env['generate_cases'](10,'Dynamic Evaluation',42)
    stress=env['generate_cases'](10,'Stress Testing',42)
    assert len(dynamic)==len(stress)==10
    assert len({c['id'] for c in dynamic})==10
    assert {c['expected_severity'] for c in dynamic}==set(env['SEVERITIES'])
    assert all(c['expected_severity'] in env['SEVERITIES'] for c in stress)
    env['execsql']('INSERT INTO evaluation_batches(id,mode,case_count,started_at) VALUES(?,?,?,?)',('B-1','Dynamic Evaluation',10,'now'))
    env['execsql']('INSERT INTO evaluation_cases(batch_id,case_id,scenario,email_json,expected_verdict,expected_severity,predicted_verdict,predicted_severity,outcome,duration_seconds,tool_count,invalid_actions,policy_compliant,trace_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('B-1','C-1','test','{}','High','High','High','High','Successful investigation',1.2,7,0,1,'[]','now'))
    assert env['evaluation_metrics'](env['query']('SELECT * FROM evaluation_cases'))['accuracy']==1
    # Controlled component ablation: incident creation alone is not verified completion.
    ablation=mail('ABLATION',1)
    incident(ablation,'High','Credential harvesting')
    naive_incident_only=bool(env['query']('SELECT * FROM incidents WHERE email_id=?',('ABLATION',)))
    full_policy_verified=env['verify_state']('ABLATION')['verified']
    assert naive_incident_only and not full_policy_verified, 'Verification must catch incomplete simulated response'
    env['tool_call']('quarantine_simulated',ablation,{})
    env['tool_call']('notify_soc',ablation,{})
    env['tool_call']('create_training',ablation,{'tip':'Never share account passwords with untrusted portals. Verify requests through your IT helpdesk.'})
    assert env['verify_state']('ABLATION')['verified']
    # Deterministic generation for reproducible scenario inputs.
    a=env['generate_cases'](10,'Dynamic Evaluation',31415)
    b=env['generate_cases'](10,'Dynamic Evaluation',31415)
    assert a==b, 'Seeded dynamic evaluation must reproduce IDs and content'
    from evaluation_suite import load_heldout, dataset_digest, baseline_severity, per_class_metrics, robustness_pairs, batch_report
    held=load_heldout()
    assert len(held)==48 and all(sum(c['expected_severity']==sev for c in held)==12 for sev in env['SEVERITIES'])
    assert dataset_digest(held)==dataset_digest(load_heldout())
    assert all(baseline_severity(c) in env['SEVERITIES'] for c in held)
    mock=[{'expected_severity':c['expected_severity'],'predicted_severity':c['expected_severity'],'email_json':json.dumps(c),'case_id':c['id'],'scenario':c['scenario'],'outcome':'Successful investigation','duration_seconds':1.0,'invalid_actions':0} for c in held]
    assert all(x['F1']==1.0 for x in per_class_metrics(mock))
    assert len(robustness_pairs(mock))==24 and all(x['Both correct'] for x in robustness_pairs(mock))
    assert batch_report(mock,{'dataset_hash':dataset_digest(held)})['severity_accuracy']==1.0
    print('PASS: held-out 48 cases, per-class metrics, seeded reproducibility, baseline, robustness pairs, JSON report, verification ablation')
    print('PASS: severity-only, Critical response, Medium archive, Low preserve-delivery, four evaluation modes, database and metrics')
