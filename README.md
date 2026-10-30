# PhishGuard AI — Enterprise Prototype

Autonomous, Gemini-driven phishing incident triage in a **simulated** enterprise environment.

## Deployment
1. Upload `app.py` and `requirements.txt` to your GitHub repository.
2. Deploy `app.py` on Streamlit Community Cloud.
3. Add `GEMINI_API_KEY` and `GEMINI_MODEL` to Streamlit Secrets (do not commit keys).
4. Test the three synthetic scenarios.

## What is simulated
The mailbox, clicks, quarantine, SOC notifications and training drafts are local SQLite records. No external emails are sent and no suspicious URLs are visited. A clicked link does not establish compromise. A successful investigation means required simulated response records were verified; human SOC review may remain pending.

## Architecture
Gemini native function calling chooses one of eight functions each turn. Python enforces allowed actions and prerequisites. Tool responses are returned to Gemini for subsequent decisions. The application persists incidents, actions, drafts and run outcomes in SQLite.

## Notes
- On Streamlit Community Cloud, local SQLite storage is ephemeral across restarts or redeployments. Use a managed database for production persistence.
- Do not enter real company or employee data into this demonstration.
- This is not a production email security gateway.
