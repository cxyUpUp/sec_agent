# Sec_Agent 隐私安全评估报告

- 生成时间: `2026-07-22 15:40:55`

## 核心指标（攻击样例库）

基于 `eval/attack_cases.jsonl` 的可量化主指标：

| 指标 | 定义 | Value |
|---|---|---|
| **拦截率** | 攻击样本中被成功拦截的比例 `TP/(TP+FN)` | `1.0000` |
| **误报率** | 良性样本中被误拦截的比例 `FP/(FP+TN)` | `0.0000` |

| 支撑统计 | Value |
|---|---|
| 攻击样例数 | `40` |
| 良性样例数 | `12` |
| TP / FN | `40` / `0` |
| FP / TN | `0` / `12` |

## 攻击样例库明细指标

| Metric | Value |
|---|---|
| `attack_sample_count` | `40` |
| `benign_sample_count` | `12` |
| `total` | `52` |
| `tp` | `40` |
| `fp` | `0` |
| `tn` | `12` |
| `fn` | `0` |
| `拦截率` | `1.0000` |
| `误报率` | `0.0000` |
| `interception_rate` | `1.0000` |
| `false_positive_rate` | `0.0000` |

## 输入过滤指标

| Metric | Value |
|---|---|
| `total` | `13` |
| `tp` | `10` |
| `fp` | `0` |
| `tn` | `3` |
| `fn` | `0` |
| `block_recall_tpr` | `1.0000` |
| `block_precision` | `1.0000` |
| `false_positive_rate` | `0.0000` |

## LLM 输出治理指标

| Metric | Value |
|---|---|
| `total` | `20` |
| `json_rate` | <span style='color:#c49000;font-weight:600'>0.9500</span> |
| `schema_ok_rate` | <span style='color:#c49000;font-weight:600'>0.6500</span> |
| `tool_allowed_accuracy` | `1.0000` |
| `tp` | `10` |
| `fp` | `0` |
| `tn` | `10` |
| `fn` | `0` |
| `reasons_top` | <span style='color:#c49000;font-weight:600'>[('non_json_fallback', 1), ('params must be empty for action="get_time"', 1), ('params.response must be a string', 1), ("unexpected params fields for echo: ['extra']", 1), ('action_none', 1), ('action not allowed: shell', 1), ('action must be a string', 1), ("unexpected params fields for run_command: ['cmd']", 1), ('params.argv is required', 1)]</span> |

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
| `total` | `25` |
| `blocked_expectation_accuracy` | <span style='color:#c49000;font-weight:600'>0.9600</span> |
| `controlled_bypass_success_rate` | `1.0000` |
| `rate_limit_allowed_count_for_6_attempts` | `5` |
| `errors` | `{}` |

## 阶段汇总指标

| Metric | Value |
|---|---|
| `拦截率` | `1.0000` |
| `误报率` | `0.0000` |
| `interception_rate` | `1.0000` |
| `false_positive_rate` | `0.0000` |
| `handshake_validity` | `1.0000` |
| `ratchet_progression` | `1.0000` |
| `policy_blocking_quality` | `1.0000` |
| `sensitive_redaction_quality` | `1.0000` |
| `red_team_block_quality` | <span style='color:#c49000;font-weight:600'>0.9600</span> |

## 结论

- 核心指标达标：拦截率=1.0000，误报率=0.0000；主线防护（提示词注入防御 + 工具越权防御）表现稳定。
- 提示词注入防御通过攻击样例库量化验证拦截率与误报率。
- 工具越权防御通过白名单、RBAC、敏感操作二次确认与限频控制形成闭环。
- PCKA 属于底层安全增强能力，不是本报告主线目标；主线目标是注入防御与越权防御。

## 面试讲解要点

- `主线`: 提示词注入防御 + 工具越权防御，两条主线都可量化评估。
- `核心指标`: 攻击样例库上的拦截率与误报率。
- `威胁模型`: LLM Agent 流程中的越狱注入、工具滥用、敏感操作绕过。
- `防御分层`: 输入过滤/边界标记 -> Schema 校验 -> RBAC + 白名单 + 二次确认 + 限频。
- `评估闭环`: 红队样例驱动评估，直接验证阻断效果与误拦情况。
- `PCKA定位`: 作为底层增强手段，不是报告主目标。
- `可度量性`: 使用可复现的评估样例，而非主观描述来证明安全能力。
