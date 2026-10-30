# PhishGuard AI — Hackathon Judging Edition

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
