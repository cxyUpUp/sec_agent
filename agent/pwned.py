import hashlib
import ssl
import urllib.error
import urllib.request


PWNED_RANGE_API = "https://api.pwnedpasswords.com/range/"


class PwnedPasswordsError(RuntimeError):
    pass


def _sha1_hex_upper(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def pwned_password_count(password: str, timeout_s: float = 8.0) -> int:
    """
    Query HIBP Pwned Passwords using k-Anonymity range API.
    Sends only the first 5 chars of SHA1(password) to the server.
    Returns: number of times this password appeared in breaches (0 if not found).
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if password == "":
        raise ValueError("password must not be empty")
    if len(password) > 256:
        raise ValueError("password too long")

    sha1 = _sha1_hex_upper(password)
    prefix, suffix = sha1[:5], sha1[5:]

    url = PWNED_RANGE_API + prefix
    req = urllib.request.Request(
        url,
        headers={
            # Some environments/providers require a UA; also useful for debugging.
            "User-Agent": "Sec_Agent/1.0 (pwned-passwords-check)",
            "Add-Padding": "true",
        },
        method="GET",
    )

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise PwnedPasswordsError(f"HTTP error from Pwned Passwords: {e.code}") from e
    except urllib.error.URLError as e:
        raise PwnedPasswordsError("Network error calling Pwned Passwords") from e

    # Body lines: "HASH_SUFFIX:COUNT"
    for line in body.splitlines():
        if ":" not in line:
            continue
        sfx, count = line.split(":", 1)
        if sfx.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                raise PwnedPasswordsError("Unexpected count format from Pwned Passwords")

    return 0


def pwned_check(password: str) -> str:
    """
    Tool-friendly wrapper returning a human-readable result.
    Never returns the original password.
    """
    count = pwned_password_count(password)
    if count <= 0:
        return "Not found in Pwned Passwords (0 times)."
    return f"Found in Pwned Passwords ({count} times). Consider changing it."

