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
    # 身份证号（中国二代身份证，18位，最后一位可能是X）
    safe = re.sub(r"\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b", "[REDACTED_ID_CARD]", safe)

    # 银行卡号（16-19位纯数字，常见卡BIN开头）
    safe = re.sub(r"\b(62|60|81|9[0-9]|5[1-5]|4[0-9])\d{12,17}\b", "[REDACTED_BANK_CARD]", safe)

    # IPv4 地址（严格过滤，排除以0或255开头的非法段，减少误报）
    safe = re.sub(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "[REDACTED_IP]", safe)

    # 通用密钥格式（带 "secret" 或 "password" 关键词的赋值）
    safe = re.sub(r"(secret|password|passwd|pwd)\s*[:=]\s*['\"]?[\w\-@#$%^&*!]{6,}['\"]?", "[REDACTED_CREDENTIAL]", safe, flags=re.I)

    # AWS Access Key（以 AKIA 开头，20位大写字母数字）
    safe = re.sub(r"\bAKIA[A-Z0-9]{16}\b", "[REDACTED_AWS_KEY]", safe)

    # GitHub Personal Access Token（以 ghp_ 开头）
    safe = re.sub(r"\bghp_[A-Za-z0-9_]{36,}\b", "[REDACTED_GITHUB_TOKEN]", safe)

    # JWT Token（三段式Base64，长度较长，降低误报阈值设为50字符）
    safe = re.sub(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{20,}\b", "[REDACTED_JWT]", safe)
    
    
    return safe