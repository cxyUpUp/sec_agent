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

Or:

```bash
python eval/export_report.py
```

### What it measures

- `input_filter`: prompt injection rule-based blocking metrics (TPR/FPR)
- `llm_output`: schema validity + tool-allow decision accuracy, plus top block reasons
- `privacy_session`: session privacy metrics for runtime tool flow
  - `redaction_success_rate`: sensitive params are masked in audit context
  - `rotation_success_rate`: session counter increments after each tool execution
  - `key_fingerprint_valid_rate`: derived tool key fingerprint is valid
- `eval_report.md`: auto-generated report with metrics tables, conclusion, and interview talking points

