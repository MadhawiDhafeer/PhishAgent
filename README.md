<div align="center">

# 🛡️ PhishAgent
### Detect. Investigate. Respond. Verify.

**An autonomous, policy-governed phishing investigation prototype**

**HUMAIN Hackathon 2026 · Challenge 3 — Autonomous Enterprise**

Built by **Madhawi Dhafeer**

![Python](https://img.shields.io/badge/Python-3.10%2B-246FE5?style=flat-square)
![Streamlit](https://img.shields.io/badge/Streamlit-App-14243B?style=flat-square)
![Gemini](https://img.shields.io/badge/AI-Gemini-246FE5?style=flat-square)
![Mode](https://img.shields.io/badge/Mode-Simulation-14243B?style=flat-square)

</div>

---

## Overview

Security teams face a constant stream of suspicious emails. Investigating each report requires gathering evidence, assessing employee exposure, assigning risk, documenting decisions, and determining the appropriate response. Manual handling can be repetitive, slow, and difficult to audit.

**PhishAgent** demonstrates how an AI agent can coordinate that workflow from investigation through verification. Using **Gemini function calling**, **deterministic security policy checks**, and **simulated response tools**, the prototype investigates synthetic phishing scenarios and produces an inspectable record of its decisions.

> **Scope:** This is a defensive **simulation**, not a production email-security integration. It does not access real mailboxes, quarantine live messages, change accounts, send notifications, or contact suspicious URLs.

## What makes PhishAgent different?

| Capability | What it demonstrates |
|---|---|
| **Agent-directed investigation** | Gemini selects tools to inspect email indicators and audit simulated employee exposure. |
| **Policy-constrained response** | Python enforces permitted simulated actions according to severity. |
| **Verified completion** | The agent cannot mark a workflow complete without verifying the required recorded actions. |
| **Explainable operations** | Incident evidence, tool decisions, audit trails, and downloadable PDF reports are available for review. |
| **Built-in evaluation** | Fixed, dynamic, stress, and held-out synthetic test modes examine classification and workflow behavior. |

## How it works

```text
Reported synthetic email
         │
         ▼
  Inspect sender, links,
  content, and indicators
         │
         ▼
 Audit synthetic recipient
 exposure and click records
         │
         ▼
 Create incident and assign
 Critical / High / Medium / Low
         │
         ▼
 Apply deterministic policy
 to simulated response tools
         │
         ▼
 Verify saved action records
         │
         ▼
 Audit trail · SOC dashboard
 PDF report · evaluation data
```

The agent uses model-directed tool calls for investigation and workflow coordination. **The model does not have unrestricted authority**: policy logic controls the allowed simulated actions, and verification checks the persisted records before successful completion.

## Security response policy

PhishAgent uses policy reference **`PG-SEC-2026.1`**.

| Severity | Simulated handling |
|---|---|
| **Critical** | Quarantine simulated copies, create SOC escalation and relevant training drafts, and record identity-response recommendations for human review. |
| **High** | Quarantine simulated copies and create SOC escalation and relevant training drafts. |
| **Medium** | Archive simulated copies. |
| **Low** | Preserve messages and record findings; no automatic containment. |

**Important:** SOC messages, employee notices, and training outputs are **drafts only**. A verified simulation is **not** proof of real containment, human SOC approval, or incident resolution.

## Product walkthrough

1. **Investigate:** Select a reported synthetic email and a synthetic reporting employee.
2. **Run the agent:** Observe tool-based email inspection, exposure auditing, incident creation, and policy-controlled simulated actions.
3. **Review evidence:** Inspect the selected severity, supporting indicators, decision timeline, and final verification status.
4. **Explore operations:** Use the **SOC Dashboard** and **Agent Audit Trail** to review incidents and execution history.
5. **Export results:** Generate a branded PDF investigation report.
6. **Evaluate:** Run the **Agent Performance & Testing** modes and inspect case-level results.

### Application workspaces

- **Investigate** — scenario selection, agent execution, findings, verification, PDF export.
- **SOC Dashboard** — incident overview and severity-based monitoring.
- **Agent Audit Trail** — recorded agent decisions and tool execution details.
- **Agent Performance & Testing** — controlled evaluation runs and exported results.

## Evaluation and reproducibility

The release includes four evaluation modes:

| Mode | Dataset | Purpose |
|---|---|---|
| **Fixed Benchmark** | 4 predefined synthetic cases | Quick functional check |
| **Dynamic Evaluation** | 4, 10, or 20 generated synthetic cases | Broader scenario coverage |
| **Stress Testing** | 4, 10, or 20 challenging synthetic cases | Probe ambiguous/adversarial patterns |
| **Held-out Dataset** | 48 frozen synthetic cases (12 per severity) | Repeatable evaluation and robustness comparisons |

Available reporting includes **per-class precision, recall, F1**, a **four-class confusion matrix**, classification coverage, workflow completion, timing, case-level traces, and a simple rule-based baseline comparison. The held-out set includes **24 rewording pairs** for consistency checks and a dataset SHA-256 digest.

**Evaluation integrity:** No accuracy or success-rate claim is made here without a corresponding completed run. Synthetic labels are controlled test labels, not independently annotated real-world ground truth. API failures, incomplete runs, and missing predictions must not be interpreted as successful classifications. Small synthetic evaluations are **not production benchmarks**.

## Technology stack

| Layer | Technology |
|---|---|
| User interface | **Streamlit** |
| Agent reasoning / tool selection | **Google Gemini API** |
| Application and policy logic | **Python** |
| Incident and execution records | **SQLite** |
| Tables and analytics | **pandas** |
| PDF report generation | **ReportLab** |

## Repository structure

```text
.
├── app.py                       # Streamlit UI, agent workflow, and simulated tools
├── evaluation_suite.py          # Evaluation helpers and metrics
├── heldout_cases.json           # Frozen synthetic evaluation dataset
├── pdf_report.py                # Branded investigation report generation
├── reporting_policy.py          # Reporting and policy support
├── requirements.txt             # Python dependencies
├── test_policy.py               # Offline policy regression tests
├── test_reporting.py            # Reporting behavior tests
├── test_final_regressions.py    # Release regression tests
├── assets/
│   ├── phishagent_logo.png      # Application branding
│   └── phishagent_icon.png      # Application icon
└── README.md
```

## Run locally

**Prerequisites:** Python 3.10+ and a Google Gemini API key with access to the configured model.

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
python -m venv .venv
```

Activate the environment:

```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create **`.streamlit/secrets.toml`** locally:

```toml
GEMINI_API_KEY = "your_gemini_api_key"
GEMINI_MODEL = "gemini-2.5-flash"
```

> Use a model available to your account. Never commit API keys or `.streamlit/secrets.toml` to GitHub.

Start the application:

```bash
streamlit run app.py
```

Open the local address displayed by Streamlit (typically `http://localhost:8501`).

## Deploy on Streamlit Community Cloud

1. Push the complete repository, including `assets/`, to GitHub.
2. Create a Streamlit Community Cloud app using **`app.py`** as the entry point.
3. Add `GEMINI_API_KEY` and `GEMINI_MODEL` in the app's **Secrets** settings.
4. Deploy and begin with a single investigation or the **4-case fixed benchmark**.
5. Export important evaluation results; the app's local SQLite storage may be reset after restarts or redeployments.

**API usage:** An investigation can require multiple Gemini calls (up to 18 tool-selection steps in the release). Larger evaluation batches can take time and consume quota.

## Offline tests

Run the included regression checks without requiring a live Gemini request:

```bash
python -m py_compile app.py evaluation_suite.py pdf_report.py reporting_policy.py
python test_policy.py
python test_reporting.py
python test_final_regressions.py
```

These checks exercise local code and policy behavior; they **do not** establish live-model performance or production security effectiveness.

## Safety, limitations, and responsible use

- **Synthetic data only:** Scenarios and employee interactions are fictional.
- **No live security actions:** Quarantine, archive, escalation, notifications, and training are simulated or drafted.
- **No real compromise verification:** A synthetic click record does not establish credential theft or account takeover.
- **Human oversight:** SOC escalation drafts and identity recommendations require human review.
- **Local persistence:** SQLite is suitable for the prototype but not durable cloud storage.
- **Model dependence:** Gemini access, API limits, and model behavior affect completion and timings.
- **No production claim:** The project demonstrates an autonomous workflow, not a deployed enterprise SOC integration.

## Roadmap

Potential next steps, **not implemented in this prototype**:

- Human-approved integrations with enterprise mail and SOC platforms.
- Durable managed storage and role-based access control.
- Broader independently labeled evaluation datasets.
- Additional security telemetry and threat intelligence sources.
- Operational monitoring, safeguards, and human-in-the-loop approvals.

## Hackathon context

**Challenge 3 — Autonomous Enterprise** asks how AI agents can own meaningful business workflows. PhishAgent explores that question in cybersecurity: rather than only labeling an email, it **investigates, assesses, coordinates policy-controlled simulated actions, verifies the recorded outcome, and exposes an audit trail**.

**Developed by Madhawi Dhafeer** · HUMAIN Hackathon 2026

---

<div align="center">

**PhishAgent — Detect. Investigate. Respond. Verify.**

*Autonomous investigation. Controlled simulation. Auditable decisions.*

</div>
