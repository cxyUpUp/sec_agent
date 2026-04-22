
## Intro
-- Design an end-to-end security execution pipeline based on "prompt injection defense + tool overreach defense", and provide a quantifiable evaluation system (including adversarial examples) for regression verification and report output. 

-- Design and implement the secure execution pipeline: input filtering → boundary marking + opportunistic session token reinforcement system prompt → tool decision-making → permission verification (tool whitelist/RBAC/sensitive operation double confirmation/rate limiting) → audit log → output de-identification.

## Run

From `Sec_Agent` root:

```bash
python -m uvicorn api.app:app --host 127.0.0.1 --port 8080 
```


- Log/Register: http://127.0.0.1:8080/ui
