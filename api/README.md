# Sec_Agent API (PCKA/Ratchet Mainline)

Sec_Agent exposes one mainline:
Input filtering �� Boundary marking + Random conversation token reinforcement system prompt �� Tool decision �� Permission verification (tool whitelist/RBAC/sensitive operation double confirmation/rate limiting) �� Audit log �� Output de-sensitization.

## Run

From `Sec_Agent` root:

```bash
python -m uvicorn api.app:app --host 127.0.0.1 --port 8080 
```


- Log/Register: http://127.0.0.1:8080/ui




