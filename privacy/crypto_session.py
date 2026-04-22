import hashlib
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RFC 3526 3072-bit MODP prime (same family as PCKA project params).
_MODP_3072_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
    "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
    "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
    "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
    "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
    "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
    "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
    "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
    "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
    "12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
    16,
)


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def _h_int(*parts: bytes, mod: int) -> int:
    # Hash to [1, mod-1], avoids zero edge cases for inverses.
    value = int.from_bytes(_sha256(*parts), "big") % mod
    return value or 1


def _int_to_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def pcka_aad_tool_payload(session_id: str, action: str, counter: int) -> bytes:
    """Binding string for AES-GCM over tool params (PCKA tool key as AEAD secret)."""
    return _sha256(
        session_id.encode("utf-8"),
        action.encode("utf-8"),
        counter.to_bytes(8, "big"),
        b"|pcka.tool|",
    )


def pcka_seal(tool_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt; tool_key must be the 32-byte output of derive_tool_key."""
    if len(tool_key) != 32:
        raise ValueError("tool_key must be 32 bytes")
    aes = AESGCM(tool_key)
    nonce = secrets.token_bytes(12)
    return nonce, aes.encrypt(nonce, plaintext, aad)


def pcka_open(tool_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(tool_key) != 32:
        raise ValueError("tool_key must be 32 bytes")
    aes = AESGCM(tool_key)
    return aes.decrypt(nonce, ciphertext, aad)


@dataclass
class CryptoSession:
    session_id: str
    sid: bytes
    prime: int
    order: int
    server_sk: int
    party_k: int
    counter: int = 0

    @classmethod
    def init(cls, user_seed: bytes, agent_seed: bytes) -> "CryptoSession":
        # PCKA-style one-pass init:
        # user computes alpha = H(sid,pw)^r; server applies sk; user unblinds => k0.
        sid = secrets.token_bytes(16)
        p = _MODP_3072_PRIME
        q = (p - 1) // 2  # safe-prime subgroup order
        sk = secrets.randbelow(q - 2) + 2
        r = secrets.randbelow(q - 1) + 1
        base = _h_int(sid, user_seed, agent_seed, mod=p - 2) + 2
        alpha = pow(base, r, p)
        beta = pow(alpha, sk, p)
        inv_r = pow(r, -1, q)
        k0 = pow(beta, inv_r, p)
        return cls(
            session_id=secrets.token_hex(8),
            sid=sid,
            prime=p,
            order=q,
            server_sk=sk,
            party_k=k0,
            counter=0,
        )

    def derive_tool_key(self, action: str) -> bytes:
        # PCKA send/server/receive shape:
        # alpha = H(k)^r', beta = alpha^sk, k' = beta^(1/r').
        # r' is deterministic from (party_k, sid, action, counter) so the same tool key
        # can be re-derived for AES-GCM open within this ratchet step (oblivious r' in a
        # distributed PCKA would come from the peer instead of this PRF).
        action_bytes = action.encode("utf-8", errors="ignore")
        counter_bytes = self.counter.to_bytes(8, "big")
        r_seed = int.from_bytes(
            _sha256(
                _int_to_bytes(self.party_k),
                self.sid,
                action_bytes,
                counter_bytes,
                b"|pcka.r|",
            ),
            "big",
        )
        r_prime = (r_seed % (self.order - 1)) + 1
        hk = _h_int(
            _int_to_bytes(self.party_k),
            b"|tool|",
            action_bytes,
            mod=self.prime - 2,
        ) + 2
        alpha = pow(hk, r_prime, self.prime)
        beta = pow(alpha, self.server_sk, self.prime)
        inv_r_prime = pow(r_prime, -1, self.order)
        k_next = pow(beta, inv_r_prime, self.prime)
        return _sha256(
            _int_to_bytes(k_next),
            self.sid,
            action_bytes,
            counter_bytes,
        )

    def rotate(self, context: str = "") -> None:
        # KRt-like rotation for server secret + party state.
        context_bytes = context.encode("utf-8", errors="ignore")
        counter_bytes = self.counter.to_bytes(8, "big")
        salt = secrets.token_bytes(16)

        # server key ratchet
        sk_material = _sha256(
            _int_to_bytes(self.server_sk),
            self.sid,
            b"|krt|",
            context_bytes,
            counter_bytes,
            salt,
        )
        self.server_sk = int.from_bytes(sk_material, "big") % self.order or 1

        # derive new party key from current state under new server secret
        base = _h_int(
            self.sid,
            _int_to_bytes(self.party_k),
            context_bytes,
            counter_bytes,
            mod=self.prime - 2,
        ) + 2
        self.party_k = pow(base, self.server_sk, self.prime)
        self.counter += 1


def create_session() -> CryptoSession:
    # Local two-party seeds for first runnable integration.
    # Replace with real user/agent enrollment when wiring distributed PCKA.
    user_seed = secrets.token_bytes(16)
    agent_seed = secrets.token_bytes(16)
    return CryptoSession.init(user_seed=user_seed, agent_seed=agent_seed)


def key_fingerprint(key: bytes, size: int = 12) -> str:
    return hashlib.sha256(key).hexdigest()[:size]


def derive_ratchet_material(key: bytes, counter: int, context: str) -> bytes:
    if not isinstance(counter, int) or counter < 0:
        raise ValueError("counter must be a non-negative integer")
    context_bytes = context.encode("utf-8", errors="ignore")
    counter_bytes = counter.to_bytes(8, "big")
    return _sha256(
        key,
        b"|ratchet|",
        context_bytes,
        counter_bytes,
    )
