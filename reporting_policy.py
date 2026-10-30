"""Auditable synthetic reporting notifications and policy metadata (no delivery)."""
from datetime import datetime, timezone

POLICY_VERSION = 'PG-SEC-2026.1'
POLICY = {
    'Critical': {'classification': 'Active compromise indicators, executive BEC, or malicious OAuth access.', 'response': 'Simulated quarantine, SOC escalation draft, training drafts for clicked recipients, identity-response recommendation; human review required.'},
    'High': {'classification': 'Targeted credential harvesting or high-privilege spear phishing.', 'response': 'Simulated quarantine, SOC escalation draft, training drafts for clicked recipients; human review required.'},
    'Medium': {'classification': 'Generalized phishing or suspicious external links.', 'response': 'Record incident and archive simulated mailbox copies.'},
    'Low': {'classification': 'Graymail, legitimate communication, or insufficient evidence for higher risk.', 'response': 'Record assessment and preserve delivery; no automatic quarantine or urgent escalation.'},
}


def save_reporter_notice(execsql, email_id, reporter, kind, body):
    """Persist a draft/in-app simulation. Never send an external message."""
    if not reporter or not reporter.endswith('@company.example'):
        raise ValueError('Choose a synthetic company employee as the reporter')
    execsql('''INSERT INTO notifications(email_id,recipient,kind,body,status) VALUES(?,?,?,?,?)
        ON CONFLICT(email_id,recipient,kind) DO UPDATE SET body=excluded.body,status=excluded.status''',
        (email_id, reporter, kind, body, 'Created (not sent)'))


def policy_reference(severity):
    rule = POLICY.get(severity)
    return {'policy_version': POLICY_VERSION, 'risk_level': severity,
            'classification_rule': rule['classification'] if rule else 'No policy classification recorded',
            'response_rule': rule['response'] if rule else 'No response rule recorded'}
