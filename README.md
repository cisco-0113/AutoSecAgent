# AutoSecAgent

面向**授权漏洞挖掘项目**的单机自动化 Agent。

以 Claude Code 为执行引擎（可指向 DeepSeek / GLM 等 Anthropic 兼容端点），把「目标 → 攻击面分类 → 授权校验 → 子代理编排 → 漏洞验证 → 报告交付」整条链路自动化，并内置**安全红线**、**对抗式防误报**与**规模化批量调度**能力。

> ⚠️ **合规红线**：所有自动化能力仅在**明确授权范围**内使用。未提供授权声明将默认拒绝执行。

---

## 核心特性

- **攻击面自动分类**：域名 / URL / IP / APK / IPA / 固件 / MQTT 一键识别，路由到对应子代理。
- **三大子代理**：Web（注入/越权/逻辑/SSRF）、Mobile（静态拆包 + frida/ADB 动态插桩）、IoT（固件逆向 / 车-云通信 / 车云平台）。
- **执行引擎桥接**：spawn headless Claude Code 子会话，流式消费真实工具输出作为漏洞 ground-truth 证据。
- **三重校验门**：grounding（落地证据）+ negation（否定式防误报，接 LLM）+ interrogation（复现要素），输出 `confirmed / probable / suspected` 三档，杜绝虚报。
- **动态差分验证**：Web 双账号差分 `[DIFF]` 证据、移动端 frida/ADB 运行时证据，把「逻辑漏洞永远卡 probable」的死锁打通。
- **组合链方法论**：多个低危发现按「数据流 + 密钥流 + 触达面」三线追踪串成攻击链，按终点危害定级。
- **规模化能力**：账号池（差分验证）、资产测绘（crt.sh 被动枚举）、批量调度（去重/续跑）。
- **质量安全**：否定门接 LLM（对抗式防误报）、速率限制 + 代理池。
- **报告交付**：Markdown（人读）+ JSON（机读）+ 按平台规范的 SRC 单独报告，自动去重分级。
- **自学习**：每次挖洞的经验回灌知识库，跨目标复用。

---

## 快速开始

### 1. 安装

```bash
# 依赖（核心运行时仅需 PyYAML）
pip install -r requirements.txt

# 可选：移动端工具链（adb / apktool），Windows 下引导下载
powershell -File tools/mobile/setup_mobile_tools.ps1
```

### 2. 配置执行引擎

AutoSecAgent 以 Claude Code CLI 为执行引擎，指向 Anthropic 兼容端点：

```bash
# 安装 Claude Code CLI（Node.js 20+）
npm install -g @anthropic-ai/claude-code

# 复制并填写 .env（API key）
cp .env.example .env
# AUTOSEC_ENGINE_PROVIDER=deepseek | deepseek-1m | glm | glm-1m
# AUTOSEC_ENGINE_API_KEY=<你的 key>

# 诊断环境是否就绪
python -m autosec.cli --check-env
```

### 3. 准备授权声明

复制示例授权文件并填写真实授权范围（目标清单 + 期限）：

```bash
cp auth.example.yaml auth.yaml
```

### 4. 运行

```bash
# 仅分类目标（无需授权）
python -m autosec.cli --target example.com --classify-only

# 完整运行（需授权声明）
python -m autosec.cli --target example.com --auth auth.yaml

# 离线演示闭环（无 claude 环境时用示例 finding 验证校验门）
python -m autosec.cli --target example.com --auth auth.yaml --dry-run

# 资产测绘（被动子域枚举，只读）
python -m autosec.cli --target example.com --recon

# 批量目标（每行一个，去重 + 断点续跑）
python -m autosec.cli --batch targets.txt --auth auth.yaml

# CTF/靶场模式（注入场景边界 + 本地 CTF 知识）
python -m autosec.cli --target app.apk --ctf-mode --auth auth.yaml
```

---

## 使用指南

### 授权声明格式（YAML）

```yaml
authorized: true
scope: "针对自建靶场/授权 SRC 项目的漏洞挖掘测试，仅限清单内目标"
targets:
  - "example.com"
  - "*.oppo.com"        # 通配符域名（后缀匹配）
  - "com.example.app"   # 包名（段级精确匹配）
start: "2026-08-15"
end: "2026-12-31"
notes: "所有测试严格限定在授权范围内"
```

授权校验支持：通配符域名后缀匹配、包名段级匹配（`com.oppo` 匹配 `com.oppo.usercenter` 但不误配 `com.oppo.usercenter2`）、段通配（`com.oppo.*`）、APK 路径嵌包名提取。

### 配置项（config.yaml）

```yaml
attacksurfaces: [web, mobile, iot]   # 允许覆盖的攻击面
engine: claude-code                   # 执行引擎
engine_provider: deepseek             # deepseek | glm
max_turns: 60                         # 单子代理轮数预算
session_seconds: 900                  # 单子代理挂钟预算
verify_enabled: true                  # 三重校验门
require_poc: true                     # confirmed 必须可复现 POC

# P5 规模化
account_pool_file: ""                 # 测试账号池 YAML（Web 差分验证）
batch_state_file: ""                  # 批量任务状态（续跑）

# P6 质量安全
negation_enabled: false               # 否定门接 LLM（未就绪自动降级）
ratelimit_rps: 1.0                    # 请求速率限制
proxy_list: []                        # 代理池
```

### 运行模式

| 模式 | 触发 | 说明 |
|---|---|---|
| 实战/SRC | 默认 | 必须有 confirmed 漏洞（含可复现 POC）才收尾 |
| CTF/靶场 | `--ctf-mode` | 必须捕获 flag 原文才收尾，注入场景边界 + CTF 知识 |
| 离线演示 | `--dry-run` | 无 claude 环境，用示例 finding 演示闭环 |

---

## 架构

```
目标输入
   │
   ├─ 授权校验（authorization.py：范围硬校验，未授权拒绝）
   ├─ 攻击面分类（classifier.py：域名/APK/固件/MQTT 指纹）
   │
   ▼
编排主代理（orchestrator.py）
   │
   ├─ 委派子代理（web / mobile / iot）
   │     ├─ 构造提示词（build_prompt：工作流 + 安全红线 + 知识回灌）
   │     ├─ 执行引擎（engine.py：spawn Claude Code，流式消费 stream-json）
   │     └─ 达标驱动续接（_run_until_goal：未达标带 Handoff 续跑）
   │
   ├─ 三重校验门（verify.py：grounding + negation + interrogation）
   ├─ 动态差分（web_dynamic.py / mobile_dynamic.py：运行时证据升级）
   │
   ▼
报告交付（report.py + srcreport.py：去重/分级/POC/修复建议，Markdown+JSON）
```

### 核心模块

| 模块 | 职责 |
|---|---|
| `orchestrator.py` | 编排主代理：授权 → 分类 → 委派 → 报告 |
| `engine.py` | Claude Code 执行引擎桥接，finding/证据流提取 |
| `verify.py` | 三重校验门（grounding / negation / interrogation） |
| `classifier.py` | 攻击面自动分类 |
| `authorization.py` | 授权范围硬校验（域名/包名精确匹配） |
| `subagents/` | web / mobile / iot 三个攻击面子代理 |
| `web_dynamic.py` | Web 双账号差分对比 + `[DIFF]` 证据 |
| `mobile_dynamic.py` | 移动端 frida/ADB 验证计划 + 运行时证据升级 |
| `knowledge.py` | CTF 知识蒸馏 + 自学习知识库 |
| `safety.py` | 安全红线（破坏性测试硬约束） |
| `report.py` / `srcreport.py` | 漏洞报告生成（去重/分级/平台规范） |
| `account_pool.py` | 账号池（角色化/差分配对） |
| `asset_recon.py` | 资产测绘（crt.sh 被动枚举） |
| `scheduler.py` | 批量调度（去重/续跑） |
| `negation.py` | 否定门（LLM 对抗式防误报） |
| `ratelimit.py` | 速率限制 + 代理池 |

---

## 安全红线

所有子代理（无论 CTF/实战模式）强制注入以下硬约束：

1. **禁止 DoS/DDoS/资源耗尽**：扫描爆破限速限次（单线程、间隔 ≥1s、单接口 ≤20 次）。
2. **禁止钓鱼与社会工程**：不发钓鱼消息、不搭钓鱼站点。
3. **禁止在线暴力破解**：仅允许对离线 hash 本地爆破，且结果不得在线重放。
4. **禁止破坏性操作**：只读优先，禁止删改数据、上传后门。
5. **严格授权范围**：只测授权清单内资产，禁止横向。
6. **数据最小化脱敏**：证据/报告不出现真实口令、手机号、令牌。

---

## 测试

```bash
python smoke_test_p1.py              # 引擎/工具治理/校验门（11 项）
python smoke_test_p2.py              # 移动端静态工作流（23 项）
python smoke_test_p2_dynamic.py      # 移动端动态工作流（20 项）
python smoke_test_p3.py              # Iot三链（25 项）
python smoke_test_p4.py              # Web 差分 + 报告（28 项）
python smoke_test_srcreport.py       # SRC 报告规范（16 项）
python smoke_test_safety.py          # 安全红线（16 项）
python smoke_test_authorization.py   # 授权精确匹配（13 项）
python smoke_test_knowledge.py       # 自学习信号识别（10 项）
python smoke_test_p5.py              # 规模化（16 项）
python smoke_test_p6.py              # 质量安全（16 项）
```

---

## 目录结构

```
AutoSecAgent/
├── autosec/                 # 核心包
│   ├── cli.py               # CLI 入口
│   ├── orchestrator.py      # 编排主代理
│   ├── classifier.py        # 攻击面分类器
│   ├── authorization.py     # 授权校验
│   ├── engine.py            # 执行引擎（Claude Code 桥接）
│   ├── verify.py            # 三重校验门
│   ├── safety.py            # 安全红线
│   ├── knowledge.py         # 自学习知识库
│   ├── web_dynamic.py       # Web 差分
│   ├── mobile_dynamic.py    # 移动端动态
│   ├── account_pool.py      # 账号池
│   ├── asset_recon.py       # 资产测绘
│   ├── scheduler.py         # 批量调度
│   ├── negation.py          # 否定门
│   ├── ratelimit.py         # 速率限制/代理池
│   ├── report.py            # 漏洞报告生成
│   ├── srcreport.py         # SRC 平台报告
│   ├── toolrun.py           # 工具治理
│   ├── audit.py             # JSONL 审计
│   ├── config.py            # 配置加载
│   └── subagents/           # web / mobile / iot 子代理
├── tools/                   # 工具配方（YAML）+ 移动端工具引导
├── smoke_test_*.py          # 冒烟测试
├── config.example.yaml      # 配置示例
├── auth.example.yaml        # 授权声明示例
└── .env.example             # 引擎 API key 示例
```

---

## 免责声明

本项目仅供**授权范围内的安全测试与教学研究**使用。使用者须遵守所在地法律法规，仅在获得明确授权的前提下对目标资产进行测试。因滥用本项目造成的任何后果，由使用者自行承担。

## License

[MIT](LICENSE)
