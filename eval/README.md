## Eval

### Run

From project root:

```bash
python -m eval.run_eval
```

Or:

```bash
python eval/run_eval.py
```

Generate markdown report:

```bash
python -m eval.export_report
```

Generate Chinese report:

```bash
python -m eval.export_report --lang=zh --output=eval/eval_report_zh.md
```

Or:

```bash
python eval/export_report.py
```

### What it measures

- `protocol_flow`: end-to-end protocol checks
  - `handshake_validity`: PCKA-style handshake can be completed and verified
  - `ratchet_progression`: secure session counter/key progress as expected
- `stages`: mainline summary metrics
  - `handshake_validity`
  - `ratchet_progression`
  - `policy_blocking_quality`
  - `sensitive_redaction_quality`
- `input_filter`: prompt injection rule-based blocking metrics (TPR/FPR)
- `llm_output`: schema validity + tool-allow decision accuracy, plus top block reasons
- `privacy_session`: session privacy metrics for runtime tool flow
  - `redaction_success_rate`: sensitive params are masked in audit context
  - `rotation_success_rate`: session counter increments after each tool execution
  - `key_fingerprint_valid_rate`: derived tool key fingerprint is valid
- `red_team`: adversarial simulation metrics
  - prompt injection variants
  - tool whitelist/schema abuse payloads
  - sensitive tool confirmation bypass attempts
  - rate-limit stress behavior
- `eval_report.md`: auto-generated report with metrics tables, conclusion, and interview talking points

