import datetime
import os
import sys
from typing import Optional

from eval.run_eval import evaluate_all


def _fmt(value):
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _severity_color(metric: str, value) -> str:
    metric_lower = metric.lower()
    lower_is_better_metrics = {"false_positive_rate", "误报率"}
    if metric_lower in {"errors", "leaked_fields", "missed_attacks", "false_alarms"} and isinstance(value, (dict, list)) and value:
        return "red"
    if metric_lower in {"fp", "fn"} and isinstance(value, (int, float)) and value > 0:
        return "red"
    if metric in {"误报率", "false_positive_rate"} and isinstance(value, (int, float)) and value > 0.0:
        return "yellow"
    if metric_lower in lower_is_better_metrics:
        return ""
    if metric in {"拦截率", "interception_rate"} and isinstance(value, (int, float)) and value < 1.0:
        return "yellow"
    if metric_lower.endswith("_quality") or metric_lower.endswith("_accuracy") or metric_lower.endswith("_rate"):
        if isinstance(value, (int, float)) and value < 1.0:
            return "yellow"
    if metric_lower == "reasons_top" and value:
        return "yellow"
    return ""


def _colorize(metric: str, value) -> str:
    text = _fmt(value)
    color = _severity_color(metric, value)
    if color == "red":
        return f"<span style='color:#d32f2f;font-weight:600'>{text}</span>"
    if color == "yellow":
        return f"<span style='color:#c49000;font-weight:600'>{text}</span>"
    return f"`{text}`"


def _section_table(title: str, data: dict) -> str:
    lines = [f"## {title}", "", "| Metric | Value |", "|---|---|"]
    for key, value in data.items():
        lines.append(f"| `{key}` | {_colorize(key, value)} |")
    lines.append("")
    return "\n".join(lines)


def _build_core_metrics_section(results: dict, language: str = "en") -> str:
    attack = results.get("attack_defense") or {}
    interception = attack.get("拦截率", attack.get("interception_rate"))
    fpr = attack.get("误报率", attack.get("false_positive_rate"))
    if interception is None and fpr is None:
        return ""

    if language == "zh":
        lines = [
            "## 核心指标（攻击样例库）",
            "",
            "基于 `eval/attack_cases.jsonl` 的可量化主指标：",
            "",
            "| 指标 | 定义 | Value |",
            "|---|---|---|",
            f"| **拦截率** | 攻击样本中被成功拦截的比例 `TP/(TP+FN)` | {_colorize('拦截率', interception)} |",
            f"| **误报率** | 良性样本中被误拦截的比例 `FP/(FP+TN)` | {_colorize('误报率', fpr)} |",
            "",
            "| 支撑统计 | Value |",
            "|---|---|",
            f"| 攻击样例数 | `{attack.get('attack_sample_count')}` |",
            f"| 良性样例数 | `{attack.get('benign_sample_count')}` |",
            f"| TP / FN | `{attack.get('tp')}` / `{attack.get('fn')}` |",
            f"| FP / TN | `{attack.get('fp')}` / `{attack.get('tn')}` |",
            "",
        ]
        return "\n".join(lines)

    lines = [
        "## Core Metrics (Attack Sample Library)",
        "",
        "Primary measurable metrics from `eval/attack_cases.jsonl`:",
        "",
        "| Metric | Definition | Value |",
        "|---|---|---|",
        f"| **Interception Rate** | Blocked attacks / all attacks `TP/(TP+FN)` | {_colorize('interception_rate', interception)} |",
        f"| **False Positive Rate** | Blocked benign / all benign `FP/(FP+TN)` | {_colorize('false_positive_rate', fpr)} |",
        "",
        "| Support Stats | Value |",
        "|---|---|",
        f"| Attack samples | `{attack.get('attack_sample_count')}` |",
        f"| Benign samples | `{attack.get('benign_sample_count')}` |",
        f"| TP / FN | `{attack.get('tp')}` / `{attack.get('fn')}` |",
        f"| FP / TN | `{attack.get('fp')}` / `{attack.get('tn')}` |",
        "",
    ]
    return "\n".join(lines)


def _build_conclusion(results: dict, language: str = "en") -> str:
    privacy = results.get("privacy_session", {})
    redaction = privacy.get("redaction_success_rate")
    rotation = privacy.get("rotation_success_rate")
    tool_acc = results.get("llm_output", {}).get("tool_allowed_accuracy")
    attack = results.get("attack_defense", {})
    tpr = attack.get("拦截率", attack.get("interception_rate"))
    if tpr is None:
        tpr = results.get("input_filter", {}).get("block_recall_tpr")
    fpr = attack.get("误报率", attack.get("false_positive_rate"))
    protocol_flow = results.get("protocol_flow", {})
    handshake = protocol_flow.get("handshake_validity")
    ratchet = protocol_flow.get("ratchet_progression")
    red_team_block = results.get("red_team", {}).get("blocked_expectation_accuracy")

    if language == "zh":
        lines = ["## 结论", ""]
        if (
            tool_acc == 1.0
            and tpr == 1.0
            and (fpr is not None and fpr == 0.0)
            and (red_team_block is not None and red_team_block >= 0.9)
        ):
            lines.append(
                f"- 核心指标达标：拦截率={_fmt(tpr)}，误报率={_fmt(fpr)}；主线防护（提示词注入防御 + 工具越权防御）表现稳定。"
            )
        else:
            lines.append(
                f"- 核心指标：拦截率={_fmt(tpr)}，误报率={_fmt(fpr)}；主线已具备基础能力，仍需结合漏拦/误报样例继续加固。"
            )

        lines.extend(
            [
                "- 提示词注入防御通过攻击样例库量化验证拦截率与误报率。",
                "- 工具越权防御通过白名单、RBAC、敏感操作二次确认与限频控制形成闭环。",
                "- PCKA 属于底层安全增强能力，不是本报告主线目标；主线目标是注入防御与越权防御。",
                "",
            ]
        )
        return "\n".join(lines)

    lines = ["## Conclusion", ""]
    if (
        tool_acc == 1.0
        and tpr == 1.0
        and (fpr is not None and fpr == 0.0)
        and (red_team_block is not None and red_team_block >= 0.9)
    ):
        lines.append(
            f"- Core metrics passed: interception_rate={_fmt(tpr)}, false_positive_rate={_fmt(fpr)}; primary defenses are stable."
        )
    else:
        lines.append(
            f"- Core metrics: interception_rate={_fmt(tpr)}, false_positive_rate={_fmt(fpr)}; continue hardening based on misses/false alarms."
        )

    lines.extend(
        [
            "- Prompt-injection defense is quantified by interception rate and false positive rate on the attack sample library.",
            "- Tool-overreach defense is evaluated by whitelist checks, RBAC, sensitive-action confirmation, and rate limits.",
            "- PCKA remains a lower-level supporting mechanism; the report focus is defense against injection and unauthorized tool use.",
            "",
        ]
    )
    return "\n".join(lines)


def _build_interview_talking_points(language: str = "en") -> str:
    if language == "zh":
        return "\n".join(
            [
                "## 面试讲解要点",
                "",
                "- `主线`: 提示词注入防御 + 工具越权防御，两条主线都可量化评估。",
                "- `核心指标`: 攻击样例库上的拦截率与误报率。",
                "- `威胁模型`: LLM Agent 流程中的越狱注入、工具滥用、敏感操作绕过。",
                "- `防御分层`: 输入过滤/边界标记 -> Schema 校验 -> RBAC + 白名单 + 二次确认 + 限频。",
                "- `评估闭环`: 红队样例驱动评估，直接验证阻断效果与误拦情况。",
                "- `PCKA定位`: 作为底层增强手段，不是报告主目标。",
                "- `可度量性`: 使用可复现的评估样例，而非主观描述来证明安全能力。",
                "",
            ]
        )
    return "\n".join(
        [
            "## Interview Talking Points",
            "",
            "- `Mainline`: prompt-injection defense + tool-authorization defense with measurable outcomes.",
            "- `Core Metrics`: interception rate and false positive rate on the attack sample library.",
            "- `Threat Model`: jailbreak-style prompt injection, tool abuse, and sensitive-action bypass attempts.",
            "- `Defense Layers`: input filtering/boundary tags -> schema validation -> RBAC + whitelist + confirmation + rate limits.",
            "- `Evaluation Loop`: red-team cases provide direct evidence of what is blocked vs. what still bypasses.",
            "- `PCKA Role`: lower-level supporting mechanism, not the primary report objective.",
            "- `Measurability`: Metrics are generated by reproducible eval cases instead of anecdotal claims.",
            "",
        ]
    )


def generate_report(output_path: Optional[str] = None, language: str = "en") -> str:
    results = evaluate_all()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = output_path or os.path.join(os.path.dirname(__file__), "eval_report.md")
    lang = "zh" if str(language).lower().startswith("zh") else "en"

    if lang == "zh":
        parts = [
            "# Sec_Agent 隐私安全评估报告",
            "",
            f"- 生成时间: `{now}`",
            "",
        ]
    else:
        parts = [
            "# Sec_Agent Privacy-Security Evaluation Report",
            "",
            f"- Generated at: `{now}`",
            "",
        ]

    core = _build_core_metrics_section(results, language=lang)
    if core:
        parts.append(core)

    if "attack_defense" in results:
        # Keep detailed table but hide verbose miss lists in the main table view.
        detail = {
            k: v
            for k, v in results["attack_defense"].items()
            if k not in {"missed_attacks", "false_alarms"}
        }
        parts.append(
            _section_table(
                "攻击样例库明细指标" if lang == "zh" else "Attack Sample Library Detail Metrics",
                detail,
            )
        )
    if "input_filter" in results:
        parts.append(_section_table("输入过滤指标" if lang == "zh" else "Input Filter Metrics", results["input_filter"]))
    if "llm_output" in results:
        parts.append(_section_table("LLM 输出治理指标" if lang == "zh" else "LLM Output Governance Metrics", results["llm_output"]))
    if "protocol_flow" in results:
        parts.append(_section_table("协议流程指标" if lang == "zh" else "Protocol Flow Metrics", results["protocol_flow"]))
    if "privacy_session" in results:
        parts.append(_section_table("隐私会话指标" if lang == "zh" else "Privacy Session Metrics", results["privacy_session"]))
    if "red_team" in results:
        red = {
            k: v
            for k, v in results["red_team"].items()
            if k != "mismatches"
        }
        parts.append(_section_table("红队攻击指标" if lang == "zh" else "Red Team Attack Metrics", red))
    if "stages" in results:
        parts.append(_section_table("阶段汇总指标" if lang == "zh" else "Stage Summary Metrics", results["stages"]))

    parts.append(_build_conclusion(results, language=lang))
    parts.append(_build_interview_talking_points(language=lang))

    text = "\n".join(parts).strip() + "\n"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(text)
    return report_path


def main():
    language = "en"
    output_path: Optional[str] = None
    for arg in sys.argv[1:]:
        if arg.startswith("--lang="):
            language = arg.split("=", 1)[1].strip().lower()
        elif arg.startswith("--output="):
            output_path = arg.split("=", 1)[1].strip()
    path = generate_report(output_path=output_path, language=language)
    print(f"Report generated ({language}): {path}")


if __name__ == "__main__":
    main()
