"""Offline regression tests for reporting notifications, policy, and PDF output."""
import sqlite3
from reporting_policy import POLICY_VERSION, POLICY, save_reporter_notice, policy_reference
from pdf_report import build_investigation_pdf

conn = sqlite3.connect(':memory:')
conn.execute('CREATE TABLE notifications (email_id TEXT,recipient TEXT,kind TEXT,body TEXT,status TEXT, UNIQUE(email_id,recipient,kind))')
def execsql(sql, args):
    conn.execute(sql, args)
    conn.commit()
save_reporter_notice(execsql, 'PH-001', 'sara@company.example', 'Report acknowledgment', 'Received')
save_reporter_notice(execsql, 'PH-001', 'sara@company.example', 'Investigation status update', 'Verified; SOC review pending')
assert conn.execute('SELECT COUNT(*) FROM notifications').fetchone()[0] == 2
assert all(r[0] == 'Created (not sent)' for r in conn.execute('SELECT status FROM notifications'))
assert 'preserve delivery' in POLICY['Low']['response']
assert policy_reference('High')['policy_version'] == POLICY_VERSION
pdf = build_investigation_pdf(email={'id':'PH-001','sender':'x@example.test','subject':'Example'},
    incident={'risk_level':'High','reason':'Evidence-based synthetic assessment','evidence':'Suspicious URL'},
    mailbox=[], notifications=[{'kind':'Report acknowledgment','recipient':'sara@company.example','status':'Created (not sent)'}],
    trace=[{'tool':'verify_response','result':'{"verified":true,"outstanding_actions":[]}','step':1}],
    run=None, model='test-model', duration=1.0, successful=True)
assert pdf[:4] == b'%PDF' and len(pdf) > 3000
print('PASS: reporter drafts, policy reference, PDF smoke test')
