"""Offline policy regression tests; does not call Gemini or Streamlit."""
import ast, json, sqlite3, tempfile
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import re
src = Path(__file__).with_name('app.py').read_text()
tree = ast.parse(src)
names = {'db','query','execsql','record','ensure_seed','reset_case','verify_state','tool_call'}
body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
code = compile(ast.Module(body=body,type_ignores=[]),'<extracted>', 'exec')
with tempfile.TemporaryDirectory() as d:
    env = {'sqlite3':sqlite3,'Path':Path,'DB':Path(d)/'test.db','datetime':datetime,'timezone':timezone,'json':json,'re':re,'urlparse':urlparse,'SEED':{'PH-001':[('a@company.example',1),('b@company.example',0)],'PH-002':[('a@company.example',0)]},'VERDICTS':('High risk','Suspicious','Benign','Needs review'),'THREATS':('Credential harvesting','Business email compromise','Fake invoice','OAuth consent phishing','Impersonation','Malicious link','Other','None identified')}
    exec(code,env)
    e={'id':'PH-001','sender':'security@corp-verify.example','subject':'Urgent verify password','body':'Click https://bad.example/login to verify your password immediately','legitimate_domain':'company.example'}
    env['reset_case'](e)
    assert env['tool_call']('quarantine_simulated',e,{}).get('error')
    assert env['tool_call']('create_incident',e,{'verdict':'High risk'}).get('error')
    env['tool_call']('inspect_email',e,{})
    env['tool_call']('audit_exposure',e,{})
    args={'verdict':'High risk','reason':'A credential request pressures users to act immediately via an external link.','threat_type':'Credential harvesting','risk_level':'High','attack_technique':'Urgency and credential harvesting','evidence':'Sender is corp-verify.example, URL host bad.example, and message asks users to verify a password.'}
    assert not env['tool_call']('create_incident',e,args).get('error')
    assert not env['verify_state']('PH-001')['verified']
    env['tool_call']('quarantine_simulated',e,{})
    env['tool_call']('notify_soc',e,{})
    env['tool_call']('create_training',e,{'tip':'Verify password reset requests through your company portal. Never enter credentials into an unexpected link.'})
    assert env['verify_state']('PH-001')['verified']
    e2={'id':'PH-002','sender':'hr@company.example','subject':'Office hours','body':'The HR portal has updated office hours.','legitimate_domain':'company.example'}
    env['reset_case'](e2)
    env['tool_call']('inspect_email',e2,{})
    env['tool_call']('audit_exposure',e2,{})
    benign={'verdict':'Benign','reason':'The sender uses the known company domain and provides a routine office hours update.','threat_type':'None identified','risk_level':'Low','attack_technique':'None observed','evidence':'Sender hr@company.example matches company.example; there are no external links or credential requests.'}
    assert not env['tool_call']('create_incident',e2,benign).get('error')
    assert env['verify_state']('PH-002')['verified']
    assert env['tool_call']('quarantine_simulated',e2,{}).get('error')
    print('PASS: high-risk safeguards, prerequisites, verified remediation, benign no-quarantine, reset')
