from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _hmac_hex(key: bytes, *parts: bytes) -> str:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.hexdigest()


def _derive_dh_key(shared_secret: bytes, sid: bytes, client_nonce: str, server_nonce: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sid,
        info=b"sec-agent-ecdh|" + client_nonce.encode("utf-8") + b"|" + server_nonce.encode("utf-8"),
    )
    return hkdf.derive(shared_secret)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


@dataclass
class PendingHandshake:
    handshake_id: str
    user_id: str
    sid: bytes
    alpha: str
    beta: str
    client_nonce: str
    server_nonce: str
    dh_key: bytes
    aad: bytes
    created_at: float


@dataclass
class SecureSession:
    secure_session_id: str
    user_id: str
    session_key: bytes
    ratchet_counter: int
    created_at: float


class SecureChannelManager:
    def __init__(self) -> None:
        self._server_secret = secrets.token_bytes(32)
        self._pending: dict[str, PendingHandshake] = {}
        self._sessions: dict[str, SecureSession] = {}

    def _compute_beta(self, alpha: str, sid: bytes, client_nonce: str, server_nonce: str) -> str:
        return _hmac_hex(
            self._server_secret,
            alpha.encode("utf-8"),
            sid,
            client_nonce.encode("utf-8"),
            server_nonce.encode("utf-8"),
        )

    def start_handshake(self, user_id: str, alpha: str, client_nonce: str, client_pubkey_b64: str) -> dict:
        handshake_id = secrets.token_hex(16)
        sid = secrets.token_bytes(16)
        server_nonce = secrets.token_hex(16)
        beta = self._compute_beta(alpha, sid, client_nonce, server_nonce)

        client_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            _b64d(client_pubkey_b64),
        )
        server_private_key = ec.generate_private_key(ec.SECP256R1())
        server_public_key = server_private_key.public_key()
        server_pubkey_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        shared_secret = server_private_key.exchange(ec.ECDH(), client_pubkey)
        dh_key = _derive_dh_key(shared_secret, sid, client_nonce, server_nonce)
        aad = (
            handshake_id.encode("utf-8")
            + b"|"
            + alpha.encode("utf-8")
            + b"|"
            + beta.encode("utf-8")
        )
        self._pending[handshake_id] = PendingHandshake(
            handshake_id=handshake_id,
            user_id=user_id,
            sid=sid,
            alpha=alpha,
            beta=beta,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            dh_key=dh_key,
            aad=aad,
            created_at=time.time(),
        )
        return {
            "handshake_id": handshake_id,
            "sid": _b64e(sid),
            "beta": beta,
            "server_nonce": server_nonce,
            "server_pubkey_b64": _b64e(server_pubkey_bytes),
            "expires_in_s": 180,
        }

    def finish_handshake(
        self,
        handshake_id: str,
        encrypted_session_key_b64: str,
        nonce_b64: str,
    ) -> dict:
        pending = self._pending.get(handshake_id)
        if pending is None:
            raise ValueError("invalid handshake_id")
        if time.time() - pending.created_at > 180:
            del self._pending[handshake_id]
            raise ValueError("handshake expired")

        try:
            plaintext = _aes_gcm_decrypt(
                key=pending.dh_key,
                nonce=_b64d(nonce_b64),
                ciphertext=_b64d(encrypted_session_key_b64),
                aad=pending.aad,
            )
            payload = json.loads(plaintext.decode("utf-8"))
            session_key = _b64d(payload["session_key_b64"])
            client_proof = str(payload["client_proof"])
        except Exception as exc:
            raise ValueError("invalid encrypted session payload") from exc

        expected = _hmac_hex(
            session_key,
            b"client_finish",
            pending.alpha.encode("utf-8"),
            pending.beta.encode("utf-8"),
        )
        if not hmac.compare_digest(client_proof, expected):
            raise ValueError("invalid client proof")

        secure_session_id = secrets.token_hex(16)
        self._sessions[secure_session_id] = SecureSession(
            secure_session_id=secure_session_id,
            user_id=pending.user_id,
            session_key=session_key,
            ratchet_counter=0,
            created_at=time.time(),
        )
        del self._pending[handshake_id]

        server_proof = _hmac_hex(session_key, b"server_finish")
        return {
            "secure_session_id": secure_session_id,
            "server_proof": server_proof,
        }

    def encrypt_for_session(self, secure_session_id: str, plaintext: str) -> dict:
        sess = self._sessions.get(secure_session_id)
        if sess is None:
            raise ValueError("invalid secure_session_id")
        aad = (
            secure_session_id.encode("utf-8")
            + b"|"
            + sess.ratchet_counter.to_bytes(8, "big")
        )
        nonce, cipher = _aes_gcm_encrypt(sess.session_key, plaintext.encode("utf-8"), aad=aad)
        return {
            "nonce_b64": _b64e(nonce),
            "ciphertext_b64": _b64e(cipher),
            "ratchet_counter": sess.ratchet_counter,
        }

    def decrypt_for_session(self, secure_session_id: str, nonce_b64: str, ciphertext_b64: str) -> str:
        sess = self._sessions.get(secure_session_id)
        if sess is None:
            raise ValueError("invalid secure_session_id")
        aad = (
            secure_session_id.encode("utf-8")
            + b"|"
            + sess.ratchet_counter.to_bytes(8, "big")
        )
        plaintext = _aes_gcm_decrypt(
            key=sess.session_key,
            nonce=_b64d(nonce_b64),
            ciphertext=_b64d(ciphertext_b64),
            aad=aad,
        )
        return plaintext.decode("utf-8")

    def ratchet(self, secure_session_id: str) -> int:
        sess = self._sessions.get(secure_session_id)
        if sess is None:
            raise ValueError("invalid secure_session_id")
        sess.session_key = _sha256(
            sess.session_key,
            b"|ratchet|",
            sess.ratchet_counter.to_bytes(8, "big"),
        )
        sess.ratchet_counter += 1
        return sess.ratchet_counter

    def get_session_meta(self, secure_session_id: str) -> dict:
        sess = self._sessions.get(secure_session_id)
        if sess is None:
            raise ValueError("invalid secure_session_id")
        return {
            "secure_session_id": sess.secure_session_id,
            "user_id": sess.user_id,
            "ratchet_counter": sess.ratchet_counter,
        }


_SECURE_CHANNEL_MANAGER = SecureChannelManager()


def get_secure_channel_manager() -> SecureChannelManager:
    return _SECURE_CHANNEL_MANAGER
