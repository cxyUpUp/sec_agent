# Sec_Agent 隐私安全评估报告

- 生成时间: `2026-04-16 11:45:06`

## 输入过滤指标

| Metric | Value |
|---|---|
| `total` | `6` |
| `tp` | `4` |
| `fp` | `0` |
| `tn` | `2` |
| `fn` | `0` |
| `block_recall_tpr` | `1.0000` |
| `block_precision` | `1.0000` |
| `false_positive_rate` | `0.0000` |

## LLM 输出治理指标

| Metric | Value |
|---|---|
| `total` | `10` |
| `json_rate` | <span style='color:#c49000;font-weight:600'>0.9000</span> |
| `schema_ok_rate` | <span style='color:#c49000;font-weight:600'>0.4000</span> |
| `tool_allowed_accuracy` | `1.0000` |
| `tp` | `3` |
| `fp` | `0` |
| `tn` | `7` |
| `fn` | `0` |
| `reasons_top` | <span style='color:#c49000;font-weight:600'>[('non_json_fallback', 1), ('params must be empty for action="get_time"', 1), ('params.response must be a string', 1), ("unexpected params fields for echo: ['extra']", 1), ('action_none', 1), ('action not allowed: shell', 1), ('action must be a string', 1)]</span> |

## 协议流程指标

| Metric | Value |
|---|---|
| `handshake_validity` | `1.0000` |
| `ratchet_progression` | `1.0000` |

## 隐私会话指标

| Metric | Value |
|---|---|
| `total` | `4` |
| `redaction_success_rate` | `1.0000` |
| `rotation_success_rate` | `1.0000` |
| `key_fingerprint_valid_rate` | `1.0000` |
| `pcka_seal_roundtrip_rate` | `1.0000` |
| `leaked_fields` | `{}` |
| `errors` | `{}` |

## 红队攻击指标

| Metric | Value |
|---|---|
| `total` | `9` |
| `blocked_expectation_accuracy` | <span style='color:#c49000;font-weight:600'>0.7778</span> |
| `controlled_bypass_success_rate` | `1.0000` |
| `rate_limit_allowed_count_for_6_attempts` | `5` |
| `errors` | <span style='color:#d32f2f;font-weight:600'>{'input_filter_mismatch': 1}</span> |

## 阶段汇总指标

| Metric | Value |
|---|---|
| `handshake_validity` | `1.0000` |
| `ratchet_progression` | `1.0000` |
| `policy_blocking_quality` | `1.0000` |
| `sensitive_redaction_quality` | `1.0000` |
| `red_team_block_quality` | <span style='color:#c49000;font-weight:600'>0.7778</span> |

## 结论

- 当前主线防护已具备基础能力，但红队阻断和规则覆盖仍需加固后再用于面试/演示级发布。
- 提示词注入防御通过输入过滤、边界标记与对抗样例进行验证，当前仍存在少量红队漏拦样例。
- 工具越权防御通过白名单、RBAC、敏感操作二次确认与限频控制形成闭环。
- PCKA 属于底层安全增强能力，不是本报告主线目标；主线目标是注入防御与越权防御。

## 面试讲解要点

- `主线`: 提示词注入防御 + 工具越权防御，两条主线都可量化评估。
- `威胁模型`: LLM Agent 流程中的越狱注入、工具滥用、敏感操作绕过。
- `防御分层`: 输入过滤/边界标记 -> Schema 校验 -> RBAC + 白名单 + 二次确认 + 限频。
- `评估闭环`: 红队样例驱动评估，直接验证阻断效果与误拦情况。
- `PCKA定位`: 作为底层增强手段，不是报告主目标。
- `可度量性`: 使用可复现的评估样例，而非主观描述来证明安全能力。
