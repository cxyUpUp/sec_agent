# Sec_Agent

带安全防护的 LLM Agent 演示项目：在可调用工具的对话能力之上，重点实现**提示词注入防御**与**工具越权防御**，并提供可量化评估与红队测试。

## 功能概览

| 能力 | 说明 |
|------|------|
| 安全 Agent 主线 | 输入过滤 → 边界标记 / Session Token → LLM 决策 → Schema 校验 → 工具授权 → 审计 → 输出脱敏 |
| 工具调用治理 | 工具白名单、RBAC、敏感操作二次确认、限频 |
| 隐私会话 | PCKA / Ratchet 会话密钥、工具参数密封、计数器轮转、敏感字段脱敏 |
| 本地敏感任务 | 密码泄露检测（不经 LLM）、Base64 解码（禁止「解码并执行」） |
| Web API + UI | FastAPI 服务、注册登录、普通/加密聊天、评测接口 |
| 自动化评测 | 注入拦截、Schema/工具决策、协议握手与棘轮、隐私会话、红队对抗 |

## 安全主线

```
用户输入
  → 提示词注入检测（规则 / 正则 / Base64 载荷探测）
  → Session Token + 边界标记强化系统提示
  → LLM 输出解析（JSON Schema）
  → 工具授权（白名单 / RBAC / 二次确认 / 限频）
  → PCKA 密封参数 + 审计日志
  → 工具执行
  → 输出脱敏
```

主线目标是**注入防御**与**越权防御**；PCKA/Ratchet 是底层会话隐私增强，不是业务主目标。

## 内置工具

### 通用

| Action | 说明 | 敏感 | 限频（默认） | 最低角色 |
|--------|------|------|--------------|----------|
| `get_time` | 返回当前时间 | 否 | 20 / 60s | viewer |
| `echo` | 回显文本 | 否 | 30 / 60s | viewer |
| `pwned_check` | 密码泄露检测（Have I Been Pwned 风格） | 是 | 5 / 60s | user |

### Coding（沙箱工作区）

文件与命令默认限制在 `SEC_AGENT_WORKSPACE`（未设置时为项目根目录），禁止路径穿越；`run_command` 仅接受 `argv` 列表（无 shell），二进制白名单为 `python` / `python3` / `py` / `git`（git 子命令再白名单）。

| Action | 参数示例 | 说明 | 敏感 | 限频 | 最低角色 |
|--------|----------|------|------|------|----------|
| `list_dir` | `{"path":"."}` | 列出目录 | 否 | 40 / 60s | viewer |
| `read_file` | `{"path":"README.md","offset":1,"limit":200}` | 按行读取 | 否 | 40 / 60s | viewer |
| `search_text` | `{"pattern":"TODO","path":".","glob":"*.py"}` | 正则搜索 | 否 | 30 / 60s | viewer |
| `glob_files` | `{"pattern":"**/*.py","path":"agent"}` | 按 glob 找文件 | 否 | 30 / 60s | viewer |
| `write_file` | `{"path":"a.py","content":"..."}` | 写入/新建文件 | 是 | 10 / 60s | user |
| `str_replace` | `{"path":"a.py","old_string":"...","new_string":"..."}` | 唯一匹配替换 | 是 | 20 / 60s | user |
| `run_command` | `{"argv":["python","-c","print(1)"],"timeout_s":15}` | 受控命令执行 | 是 | 8 / 60s | admin |

敏感工具需先确认（有效期约 120 秒）：

```text
/confirm write_file
/confirm str_replace
/confirm run_command
/confirm pwned_check
```

或通过 API：`POST /tools/confirm`。

## 本地命令（不经 LLM）

```text
/pwned <password>
pwned <password>
查泄露 <password>
泄露检测 <password>

/confirm <action>

帮我解码这段base64：<payload>
/base64 <payload>
```

「解码并执行」会被拦截；解码结果若命中注入规则同样阻断。

## 目录结构

```text
Sec_Agent/
├── main.py                 # Agent 主循环（CLI 入口）
├── agent/                  # LLM 调用、Action 解析、工具实现
├── security/               # 输入过滤、授权、Schema、审计、输出脱敏
├── privacy/                # PCKA/Ratchet 会话与安全信道
├── api/                    # FastAPI 服务与鉴权
├── frontend/               # Demo UI（/ui）
├── eval/                   # 评测用例、红队、报告导出
├── data/                   # 用户数据等
└── requirements.txt
```

## 环境准备

```bash
pip install -r requirements.txt
```

依赖：`openai`、`fastapi`、`uvicorn`。调用 LLM 前请配置对应的 OpenAI 兼容 API Key / Base URL（见 `agent/llm.py`）。

## 快速开始

### 1. 命令行

```bash
python main.py
```

### 2. Web API + UI

在项目根目录执行：

```bash
python -m uvicorn api.app:app --host 127.0.0.1 --port 8080
```

- 控制台 UI：http://127.0.0.1:8080/ui
- OpenAPI 文档：http://127.0.0.1:8080/docs
- 健康检查：http://127.0.0.1:8080/health

### 3. 评测

```bash
python -m eval.run_eval
python -m eval.export_report
python -m eval.export_report --lang=zh --output=eval/eval_report_zh.md
```

更多说明见 [eval/README.md](eval/README.md)。

## 主要 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/auth/register` | 注册 |
| `POST` | `/auth/login` | 登录，返回 Bearer Token |
| `GET` | `/auth/me` | 当前用户 |
| `POST` | `/chat` | 普通聊天（需鉴权，返回 answer + security_trace） |
| `POST` | `/tools/confirm` | 敏感工具二次确认 |
| `POST` | `/pcka/handshake/start` | 安全信道握手开始 |
| `POST` | `/pcka/handshake/finish` | 安全信道握手完成 |
| `POST` | `/chat/secure` | 加密聊天（密文进、密文出） |
| `GET` | `/session/{user_id}` | 会话快照（PCKA counter / key_id） |
| `GET` | `/eval` | 即时评测指标 |
| `POST` | `/eval/report` | 生成评测报告 |

除握手 finish / 加密聊天等按设计放宽的接口外，业务接口一般使用：

```http
Authorization: Bearer <token>
```

## 评测维度

- **input_filter**：注入拦截 TPR / FPR
- **llm_output**：JSON Schema 合法性、工具放行准确率
- **protocol_flow**：握手有效性、棘轮计数推进
- **privacy_session**：参数脱敏、密钥轮转、指纹校验、密封往返
- **red_team**：注入变体、白名单/Schema 滥用、确认绕过、限频压力

## 设计要点（面试可讲）

1. **注入与越权是两条可量化主线**，规则过滤 + Schema + Guard 形成闭环。
2. **敏感工具默认拒绝**，需显式 `/confirm` 或 API 确认，并受限频约束。
3. **密码泄露检测本地直达工具**，避免把明文密码送入 LLM。
4. **审计链路对敏感字段脱敏**，工具参数可经 PCKA 密封后再记录上下文。
5. **红队与指标报告**用于验证防护是否达标，而非只靠「感觉安全」。

## 许可证

仅供学习与演示使用。
