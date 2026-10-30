# PhishAgent — Hackathon Judging Edition

A Streamlit + Gemini **simulated** autonomous enterprise phishing investigation agent. It uses **only Critical / High / Medium / Low severity**, with no separate verdict. Low includes benign and uncertain mail; it is observation-only and is never automatically quarantined.

## Features

- Model-directed tool calls for inspection, simulated employee exposure auditing, incident documentation, severity-dependent simulated response, and verification.
- Critical: quarantine simulation + SOC draft + clicked-user training drafts + identity-response **recommendation** (no real account actions).
- High: quarantine simulation + SOC draft + clicked-user training drafts.
- Medium: archive simulated copies. Low: record findings and preserve messages.
- High-contrast SOC Dashboard, agent audit trail, decision timeline, and Agent Performance & Testing.
- Four evaluation modes: **Fixed Benchmark** (4 cases), **Dynamic Evaluation** (4/10/20 new synthetic cases), **Stress Testing** (4/10/20 adversarial/ambiguous synthetic cases), and **Held-out Dataset** (48 frozen synthetic cases, 12 per severity, including 24 rewording pairs).
- Per-class precision, recall, F1; four-class confusion matrix; investigation completion; timing; simple rule-baseline comparison; held-out robustness pair consistency; case evidence and audit inspection; JSON/CSV export; batch metadata and dataset SHA-256.
- A controlled **verification ablation regression** proves that creating an incident alone is insufficient for successful completion.

## Installation and deployment

1. Commit **all** these files at the root of your GitHub repository: `app.py`, `evaluation_suite.py`, `heldout_cases.json`, `requirements.txt`, `test_policy.py`.
2. Deploy `app.py` on Streamlit Community Cloud.
3. Set secrets in Streamlit settings (never commit actual keys):

   ```toml
   GEMINI_API_KEY = "your_api_key"
   GEMINI_MODEL = "your_available_model"
   ```

4. Start with **Fixed Benchmark (4)**; next run **Dynamic (4)**, **Stress (4)**. Run the **Held-out Dataset (48)** only when API quotas and time permit. One case can require up to 18 Gemini tool-selection calls.
5. Download the evaluation JSON report and keep it outside Streamlit Cloud; local SQLite history can be lost on restart.

## Offline reproducibility

```bash
python -m py_compile app.py evaluation_suite.py
python test_policy.py
```

No API key is required for offline regression tests. The same random seed reproduces the synthetic Dynamic/Stress case inputs, but **Gemini outputs are not guaranteed deterministic**. The held-out corpus is frozen and versionable; the app stores its content digest and the model identifier in batch metadata. JSON exports include case-level predictions and timings.

## Judging criteria evidence

| Criterion | Evidence to demonstrate |
|---|---|
| Task Performance | Held-out severity accuracy, per-class metrics, four-class confusion matrix. |
| Robustness & Adaptation | Stress cases; 24 held-out paired rewordings and consistency results. |
| Evaluation & Iteration | Saved batch reports, seeded test inputs, policy regression suite, verification ablation. |
| Technical Judgment & Creativity | Rule baseline vs. autonomous multi-tool agent; deterministic guardrails vs. model-directed selection. |
| Engineering Quality | SQLite migrations, explicit failure statuses, regression tests, versioned dataset, SHA-256 and exports. |
| Communication | SOC workflow, audit timeline, metrics, trade-offs, limitations. |

## Honest limitations

- **All enterprise operations are simulated**. No actual mailbox quarantine, SOC delivery, account isolation, password revocation, or employee training delivery.
- The 48 frozen hold-out labels are **scenario-authored synthetic labels**, not independently human-reviewed ground truth. The cases are related variations of a small set of scenario families, so they do **not** establish real-world generalization. Before claiming objective performance on independently reviewed held-out data, have a separate reviewer check labels, add genuinely new families, and avoid prompt tuning on the hold-out.
- The keyword baseline is intentionally simple and transparent. An agent advantage is **not assumed**; compare measured results honestly.
- The verification ablation is an **offline controlled policy test**, not an empirical agent-versus-agent performance experiment. A complete ablation study would rerun the same frozen dataset with components disabled, under matched model settings, and compare results.
- Synthetic `Critical` examples indicate high-severity requests, not proof of real compromise. Simulated employee clicks do not prove account takeover.
- Classification accuracy alone does not prove safe response behavior. Policy verification checks persisted simulated actions, not real-world remediation.
- Streamlit Community Cloud's local SQLite filesystem is ephemeral. Store exported reports externally for durable comparisons.
- Large evaluation runs can consume significant Gemini quota and take several minutes; model/network failures should count as unsuccessful investigations rather than be excluded.


### Branded PDF investigation reports
The Investigation Workspace exports a professional PDF using `pdf_report.py` and ReportLab. The report includes the risk assessment, synthetic employee exposure, simulated response actions, verification findings, and a concise tool audit. Install dependencies from `requirements.txt`. PDF reports are generated in memory and are not emailed or uploaded.

## Reporting and policy update

- The Investigation Workspace now asks for a **synthetic reporting employee**. An acknowledgment draft is saved when the investigation starts and a status-update draft is saved after completion. Neither is delivered externally.
- Critical and High investigations also create a separate SOC escalation **draft** under existing risk-based policy. Verified workflow completion does not mean SOC approval or incident resolution.
- The Investigation Workspace and PDF show the policy reference `PG-SEC-2026.1`, including classification guidance and severity-specific response requirements. Gemini interprets the email evidence; deterministic Python code restricts and verifies simulated response actions.
- The **Agent Performance & Testing** workspace runs without a reporting employee; benchmark evaluation behavior remains unchanged.
- Run `python test_policy.py` and `python test_reporting.py` to validate policy and reporter notification behavior.

## PhishAgent rebranding

The product name is now **PhishAgent** in the application, exported report names, PDF branding, and documentation. The existing `phishguard.db` SQLite filename is deliberately retained for backward compatibility with prior local data. The policy identifier `PG-SEC-2026.1` is also retained because it is a stable policy version reference, not product branding. No security logic, email scenarios, or evaluation behavior was changed as part of the rename.


### Brand assets

The PhishAgent logo is stored at `assets/phishagent_logo.png` and displayed in the Streamlit sidebar. The matching icon at `assets/phishagent_icon.png` is used as the browser tab favicon. Keep the `assets/` folder when deploying.

## Final release corrections
- Operational and evaluation records are separated with an additive `source` column. Existing `phishguard.db` is retained for compatibility. Legacy `EV-*` records are attributed to evaluation; older fixed-benchmark records with `PH-*` identifiers cannot be reliably distinguished retrospectively.
- Fixed and held-out benchmark runs use isolated evaluation IDs to prevent resetting operational PH cases.
- Classification accuracy is measured only on cases with a valid severity; classification coverage and workflow completion are shown separately. A batch with no predictions displays `N/A` accuracy.
- Tool success displays `N/A` when no tools ran. This remains an approximate attempt metric, not an end-to-end tool reliability guarantee.
- The configured Gemini model can be overridden with `GEMINI_MODEL` in Streamlit Secrets. Default: `gemini-2.5-flash`. Availability and API quota depend on your Google account.
- The SQLite database is local to the Streamlit runtime and may be reset when Streamlit Community Cloud restarts.

### Streamlit Secrets
```toml
GEMINI_API_KEY = "your-api-key"
GEMINI_MODEL = "gemini-2.5-flash"
```
Do not commit your actual API key or `.streamlit/secrets.toml` to GitHub.

### Offline verification
```bash
python test_policy.py
python test_reporting.py
python test_final_regressions.py
```
These checks do not make live Gemini API calls. Validate the configured model and a 4-case benchmark after deployment.


### PDF report branding and Century Gothic
The PDF running header now includes the PhishAgent shield icon from `assets/phishagent_icon.png`.
The report uses **Century Gothic** when you provide your own properly licensed TrueType font files at:
- `assets/fonts/CenturyGothic.ttf`
- `assets/fonts/CenturyGothicBold.ttf`

Without these files, PDF generation safely falls back to Helvetica/Helvetica-Bold.
Font files are not included in this release.

## Branding and attribution

PhishAgent was developed by **Madhawi Dhafeer**. The sidebar uses a dark navy palette (#14243B) and the PDF report includes the project icon and developer attribution. The PDF uses Century Gothic only if you provide properly licensed `assets/fonts/CenturyGothic.ttf` and `CenturyGothicBold.ttf`; otherwise it falls back to Helvetica.
