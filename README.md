# PhishGuard AI — Autonomous Enterprise Security (vNext)

Streamlit + Gemini function-calling defensive phishing investigation **simulation**.

## What's new
- **Severity-only classification**: `Critical`, `High`, `Medium`, `Low`. No separate verdict classification. Low includes low-risk, legitimate and uncertain emails; it is not proof of phishing.
- **Risk-aware simulated response**: Critical/High quarantine copies and create SOC/training drafts; Critical additionally records identity response recommendations (no account changes); Medium archives simulated copies; Low moves copies to simulated junk; Low is routed to simulated junk according to the requested four-tier policy, including routine mail; this may be overly aggressive for production use.
- **Agent Performance & Testing**: fixed four-case benchmark, dynamic controlled synthetic emails, stress tests, configurable 4/10/20 cases and optional random seed.
- **Evaluation history**: saved batch IDs, case-level evidence and traces, severity accuracy, precision/recall, false positive/negative rates, workflow verification, approximate tool success and execution time.
- **SOC Dashboard**: severity filtering and operational metrics; agent timing moved to performance page.
- **Readable investigation timeline** with key tool findings and optional raw JSON.
- **SQLite schema migration** via `CREATE TABLE IF NOT EXISTS`, including evaluation tables.

## Deploy
1. Upload `app.py`, `requirements.txt` and optionally `test_policy.py` to your GitHub repo.
2. Streamlit Community Cloud: set main file to `app.py`.
3. Add secrets in app settings:
   ```toml
   GEMINI_API_KEY = "your_api_key_here"
   GEMINI_MODEL = "your_available_gemini_model"
   ```
4. Reboot/redeploy the app. The schema updates automatically.
5. Run **Investigate** and then **Agent Performance & Testing** (start with 4 cases; every case may make many Gemini calls).

## Validation
`python test_policy.py` performs offline policy and SQLite regression tests. `python -m py_compile app.py` checks syntax. Neither calls Gemini.

## Important limitations
- This is a **simulation**. No real mailbox, account, SOC delivery or identity provider is modified.
- Synthetic scenario labels are generated from controlled templates, not independent human annotation. Metrics on small synthetic batches are not production detection benchmarks.
- The same Gemini agent investigates generated emails, but generated emails are not produced by Gemini; their labels are predetermined. A random seed reproduces scenario selection/content patterns but not unique IDs or model outputs.
- `phishguard.db` is local SQLite. On Streamlit Community Cloud the filesystem may reset on redeploy/restart; evaluation history is not durable without an external database.
- Model behavior and API quota/availability affect workflow completion and timings. No Gemini end-to-end run was executed by the offline tests.
- Existing incident records are normalized to one of the four severity levels on startup. Legacy database column names remain internally for backward compatibility but are not used as a separate classification.
