# Sec_Agent Backend v1

## Run

From `Sec_Agent` root:

```bash
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --reload
```

API docs:

- Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

## Endpoints

- `GET /` basic service info
- `GET /health` health check
- `POST /chat` run secure agent with privacy trace
- `POST /pcka/handshake/start` start OPRF-style secure channel handshake
- `POST /pcka/handshake/finish` finish handshake and get secure session id
- `POST /chat/secure` encrypted chat over secure session (ratchet per turn)
- `GET /session/{user_id}` get current privacy session snapshot
- `GET /eval` run all security/privacy metrics
- `POST /eval/report` generate `eval/eval_report.md`

## Example Requests

```bash
curl -X POST "http://127.0.0.1:8000/chat" ^
  -H "Content-Type: application/json" ^
  -d "{\"user_id\":\"demo_user\",\"message\":\"tell me time\"}"
```

```bash
curl "http://127.0.0.1:8000/session/demo_user"
```

Secure handshake examples:

```bash
curl -X POST "http://127.0.0.1:8000/pcka/handshake/start" ^
  -H "Content-Type: application/json" ^
  -d "{\"user_id\":\"secure_demo\",\"alpha\":\"<client_alpha_hex>\",\"client_nonce\":\"<client_nonce>\",\"client_pubkey_b64\":\"<client_ecdh_pubkey_b64>\"}"
```

```bash
curl -X POST "http://127.0.0.1:8000/pcka/handshake/finish" ^
  -H "Content-Type: application/json" ^
  -d "{\"handshake_id\":\"<handshake_id>\",\"encrypted_session_key_b64\":\"<aes_gcm_cipher_b64>\",\"nonce_b64\":\"<aes_gcm_nonce_b64>\"}"
```
