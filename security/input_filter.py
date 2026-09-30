import re
import secrets
from typing import Any

from security.classifier import assess
from security.normalize import scan_forms


BLOCK_PATTERNS = [
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "reveal hidden",
    "jailbreak",
    "忽略之前",
    "忽略以上",
    "越狱",
]


SUSPICIOUS_REGEXES = [
    re.compile(r"(ignore|遗忘|忘记|忽略|disregard)\s+(之前的|上述|全部|所有|previous|above|all)\s+(指令|约束|规则|instructions|constraints)", re.I),
    re.compile(r"(base64|b64)\s*(decode|解码)", re.I),
    re.compile(r"(print|reveal|show|输出|泄露|告诉).{0,40}(system\s*prompt|系统提示词|系统指令|developer\s*prompt)", re.I),
    re.compile(r"(执行|运行).{0,40}(命令|shell|powershell)", re.I),
    re.compile(r"(你是|你现在是|你现在扮演|you are|act as|pretend to be).{0,40}(不受任何限制|没有任何约束|no restrictions|without any limits)", re.I),
    re.compile(r"(开发者模式|developer\s*mode)", re.I),
    re.compile(r"(输出|打印|显示|print|show|reveal|display).{0,40}(所有|全部|all|the\s+whole|entire).{0,40}(规则|约束|prompt|指令)", re.I),
    re.compile(r"(重新设置|重置|reset|override|覆盖).{0,40}(角色|设定|身份|persona|role|setting)", re.I),
    re.compile(r"(你现在拥有|你拥有|你有|你具备|you have|you possess).{0,40}(管理员|超级用户|根权限|root|admin|superuser|系统级|system-level)", re.I),
    re.compile(r"(提升|获取|获得|escalate|gain|acquire).{0,40}(权限|privilege|access|level)", re.I),
    re.compile(r"(绕过|bypass|circumvent).{0,40}(安全|防护|检测|审查|security|filter|guardrail|content\s+policy)", re.I),
    re.compile(r"(base64|b64|hex|十六进制|unicode|url\s*encode).{0,20}(解码|解密|decode|decrypt)", re.I),
    re.compile(r"(反转|倒序|倒置|reverse|invert).{0,20}(字符串|文本|content|string)", re.I),
    re.compile(r"(发送|上传|传输|send|upload|post|exfiltrate).{0,20}(到|至|to).{0,20}(http|https|ftp|url|webhook|endpoint)", re.I),
    re.compile(r".{0,5}(执行|运行|run|execute).{0,5}(命令|command|shell|cmd)", re.I),
    re.compile(r"\b(\w{1,12}\s+){1,6}(执行|运行|execute|run)\b", re.I),
    re.compile(r"(请记住|记住|remember|first).{0,40}(接下来|之后|later|then).{0,40}(执行|运行|execute|run)", re.I),
    re.compile(r"(#|<!--|/\*).{0,40}(指令|命令|规则|instruction|command|rule)", re.I),
    re.compile(r"[\[{<]\s*(SYS|系统|system|指令|INST|prompt)\s*[\]}>]", re.I),
    re.compile(r"(无论|不管|regardless|no matter).{0,40}(什么|what|哪种|which).{0,40}(回答|输出|say|output)", re.I),
    re.compile(r"(as\s+json|as\s+xml|as\s+markdown|格式化).{0,40}(绕过|避开|脱离|bypass|escape)", re.I),
]


_EXPLAIN_PROMPT = re.compile(
    r"(explain|what\s+(is|does|do)|介绍|说明|含义|means?).{0,48}(system\s*prompt|developer\s*prompt|系统提示)",
    re.I,
)
_ATTACK_VERB = re.compile(
    r"(ignore|disregard|reveal|print|dump|jailbreak|bypass|泄露|输出|忽略|绕过|越狱|打印)",
    re.I,
)


def _explanatory_mention(text: str) -> bool:
    return bool(_EXPLAIN_PROMPT.search(text)) and not _ATTACK_VERB.search(text)


def detect_injection(text: str) -> dict[str, Any]:
    original = str(text)
    forms = scan_forms(original)
    reasons: list[str] = []
    risk_score = 0.0

    for form in forms:
        normalized = form.lower()
        if any(pattern in normalized for pattern in BLOCK_PATTERNS):
            reasons.append("keyword_pattern")
            risk_score += 0.7
            break
    if risk_score < 0.7:
        for form in forms:
            if any(rx.search(form.lower()) for rx in SUSPICIOUS_REGEXES):
                reasons.append("suspicious_regex")
                risk_score += 0.7
                break

    blocked = risk_score >= 0.7
    classifier_info: dict[str, Any] = {"skipped": blocked}
    policy_version = ""
    if not blocked:
        verdict = assess(original, "input")
        labels = list(verdict.labels)
        if _explanatory_mention(original):
            labels = [label for label in labels if label != "prompt_injection"]
        classifier_info = {
            "skipped": False,
            "labels": labels,
            "scores": verdict.scores,
            "degraded": verdict.degraded,
            "elapsed_ms": round(verdict.elapsed_ms, 3),
        }
        policy_version = verdict.policy_version
        if labels:
            blocked = True
            reasons.append("classifier:" + ",".join(labels))
            risk_score = max(risk_score, verdict.risk_score)
        elif verdict.blocked and verdict.degraded:
            blocked = True
            reasons.append(verdict.reason)
            risk_score = max(risk_score, verdict.risk_score)

    if not blocked and not _explanatory_mention(original):
        from security.context_guard import judge_prompt

        context_label, context_reason = "safe", ""
        for form in forms:
            context_label, context_reason = judge_prompt(form)
            if context_label == "unsafe":
                break
        if context_label == "unsafe":
            blocked = True
            reasons.append(context_reason or "context_guard")
            risk_score = max(risk_score, 0.8)

    return {
        "blocked": blocked,
        "risk_score": round(min(risk_score, 1.0), 3),
        "reasons": reasons,
        "classifier": classifier_info,
        "policy_version": policy_version,
    }


def build_session_token() -> str:
    return secrets.token_hex(16)


def wrap_user_input(user_input: str) -> str:
    return (
        "[USER_INPUT]\n"
        f"{user_input}\n"
        "[/USER_INPUT]"
    )