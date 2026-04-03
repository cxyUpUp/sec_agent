import re

def filter_output(text: str):
    if text is None:
        return ""
    safe = str(text)
    # phone
    safe = re.sub(r"\b1\d{10}\b", "[REDACTED_PHONE]", safe)
    # common key/token patterns
    safe = re.sub(r"api[_-]?key\s*[:=]\s*[\w\-]{8,}", "[REDACTED_API_KEY]", safe, flags=re.I)
    safe = re.sub(r"token\s*[:=]\s*[\w\-\.]{8,}", "[REDACTED_TOKEN]", safe, flags=re.I)
    # OpenAI-like keys
    safe = re.sub(r"\bsk-[A-Za-z0-9\-_]{10,}\b", "[REDACTED_SECRET]", safe)
    # email
    safe = re.sub(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]", safe)
    return safe