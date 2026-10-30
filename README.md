# PhishGuard AI — Enhanced Hackathon Edition

A Streamlit demonstration of an autonomous, policy-controlled phishing investigation agent using native Gemini function calling and **synthetic data only**.

## What's improved

- Four cases: credential phishing, benign HR announcement, suspicious invoice, and ambiguous external vendor request.
- Agent selects tools iteratively, observes outputs, and must verify simulated response records before marking the investigation successful.
- Incident creation requires prior inspection and exposure audit, detailed factual explanation, concrete evidence, and internally consistent classification.
- Policy gates prevent benign quarantine and prevent unsupported high-risk containment.
- Simulated quarantine, SOC notification drafts, training drafts, persistent SQLite audit records.
- Each run starts with a reset of that scenario's synthetic case data to avoid stale prior actions influencing the outcome.
- Evaluation Lab runs **four actual Gemini investigations** and saves predicted vs. expected verdict, workflow outcome, and duration.
- Audit Trail, SOC dashboard, JSON report and CSV exports.

## Deploy on Streamlit Community Cloud

1. Upload `app.py` and `requirements.txt` to your GitHub repository.
2. Set Streamlit Secrets:

   ```toml
   GEMINI_API_KEY = "YOUR_KEY_HERE"
   GEMINI_MODEL = "YOUR_SUPPORTED_GEMINI_MODEL"
   ```

3. Deploy or reboot the Streamlit app.
4. In **Investigate**, test each of the four scenarios.
5. In **Evaluation Lab**, run the four-case evaluation (this consumes Gemini API quota).
6. Review tool events under **Agent Audit Trail**.

## Important limitations

- No real mailboxes, external URLs, quarantine APIs, or outgoing notifications are used.
- Successful investigation means the required **simulated** response records were verified; escalated cases still require human SOC review.
- The four-case evaluation is a small, synthetic smoke test and does **not** establish generalizable phishing-detection accuracy.
- The agent can make classification errors; verification enforces operational record completeness and basic consistency, not ground-truth correctness.
- SQLite on Streamlit Community Cloud is ephemeral across certain restarts/redeployments. Use a managed database for real deployments.
- For a production implementation, add robust authentication, least-privilege integrations, secure secret management, rate limits, background workers, monitoring, redaction, and comprehensive evaluation.

## Offline policy checks

Run `python test_policy.py` to check core policy gates without API access.

## Files

- `app.py`: Streamlit UI, Gemini agent, SQLite tools, verification, Evaluation Lab
- `requirements.txt`: dependencies
- `test_policy.py`: offline policy regression tests
