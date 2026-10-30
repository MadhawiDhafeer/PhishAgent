"""Evaluation utilities: transparent baseline, per-class metrics and frozen synthetic hold-out."""
import hashlib
import json
from pathlib import Path

SEVERITIES = ("Critical", "High", "Medium", "Low")

def load_heldout():
    cases = json.loads(Path(__file__).with_name("heldout_cases.json").read_text(encoding="utf-8"))
    if len(cases) != 48 or any(c.get("expected_severity") not in SEVERITIES for c in cases):
        raise ValueError("Held-out dataset must contain 48 labeled four-tier cases")
    if len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Held-out case IDs must be unique")
    return cases

def dataset_digest(cases):
    payload = json.dumps(cases, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()

def baseline_severity(email):
    """Intentionally simple rule comparator; no external calls or model knowledge."""
    s = (email.get("subject", "") + " " + email.get("body", "")).lower()
    if any(t in s for t in ("wire transfer", "oauth", "offline access", "payroll bank", "dual approval")):
        return "Critical"
    if any(t in s for t in ("password and mfa", "mfa code", "mfa verification", "sso", "corporate login credentials", "corporate password")):
        return "High"
    if any(t in s for t in ("package-delivery", "password-expiration", "tracking link", "questionable payment", "external reset link")):
        return "Medium"
    return "Low"

def per_class_metrics(rows):
    rows = [r for r in rows if r.get("predicted_severity") in SEVERITIES]
    output=[]
    for label in SEVERITIES:
        tp=sum(r["expected_severity"]==label and r["predicted_severity"]==label for r in rows)
        fp=sum(r["expected_severity"]!=label and r["predicted_severity"]==label for r in rows)
        fn=sum(r["expected_severity"]==label and r["predicted_severity"]!=label for r in rows)
        support=sum(r["expected_severity"]==label for r in rows)
        output.append({"Severity":label,"Cases":support,"Precision":round(tp/(tp+fp),3) if tp+fp else None,"Recall":round(tp/(tp+fn),3) if tp+fn else None,"F1":round(2*tp/(2*tp+fp+fn),3) if 2*tp+fp+fn else None})
    return output

def robustness_pairs(rows):
    groups={}
    for r in rows:
        email=json.loads(r["email_json"])
        family=email.get("family")
        if family:
            groups.setdefault(family,[]).append(r)
    out=[]
    for family, items in sorted(groups.items()):
        if len(items)!=2: continue
        p=[r["predicted_severity"] for r in items]
        out.append({"Pair":family,"Expected":items[0]["expected_severity"],"Predictions": " / ".join(x or "No result" for x in p),"Consistent":p[0]==p[1],"Both correct":all(x==items[0]["expected_severity"] for x in p)})
    return out

def batch_report(rows, batch):
    n=len(rows)
    valid=[r for r in rows if r.get("predicted_severity") in SEVERITIES]
    return {"batch":dict(batch),"dataset_sha256":batch.get("dataset_hash"),"case_count":n,
            "severity_accuracy":sum(r["expected_severity"]==r["predicted_severity"] for r in valid)/len(valid) if valid else None, "classification_coverage":len(valid)/n if n else None,
            "baseline_accuracy":sum(baseline_severity(json.loads(r["email_json"]))==r["expected_severity"] for r in rows)/n if n else None,
            "workflow_success_rate":sum(r["outcome"]=="Successful investigation" for r in rows)/n if n else None,
            "per_class":per_class_metrics(rows),"robustness_pairs":robustness_pairs(rows),
            "cases":[{"id":r["case_id"],"scenario":r["scenario"],"expected":r["expected_severity"],"predicted":r["predicted_severity"],"workflow":r["outcome"],"seconds":r["duration_seconds"],"invalid_actions":r["invalid_actions"]} for r in rows],
            "limitations":"Synthetic scenario-authored labels; not independently adjudicated. No real security operations performed."}
