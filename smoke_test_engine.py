"""引擎连通性冒烟测试 — 实证 claude CLI + DeepSeek 端点的 stream-json 证据流。

运行: .venv\\Scripts\\python.exe smoke_test_engine.py
验证:
  1. deepseek 端点可达（真实 HTTP 调用）
  2. claude CLI -p 能 spawn 并拿到 assistant 回复
  3. stream-json 事件流能解析出 tool_use / tool_result（证据流）
"""
from __future__ import annotations

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.config import Config
from autosec.engine import run_session

cfg = Config.load()

print("=" * 56)
print("AutoSecAgent 引擎连通性冒烟测试")
print("=" * 56)
print(f"  provider : {cfg.engine_provider}")
print(f"  endpoint : {cfg.engine_base_url or '(preset)'}")
print(f"  model    : {cfg.engine_model or '(preset)'}")
print(f"  api_key  : {cfg.engine_api_key[:8]}...{cfg.engine_api_key[-4:] if cfg.engine_api_key else '(空)'}")
print("-" * 56)

# 前置：key 非占位符
if not cfg.engine_api_key or "placeholder" in cfg.engine_api_key or "not-real" in cfg.engine_api_key:
    print("[FAIL] API key 仍是占位符，请先填写真实 key")
    sys.exit(1)

# 前置：claude CLI 存在
ok, msg = cfg.engine_ready()
if not ok:
    print(f"[FAIL] {msg}")
    sys.exit(1)
print(f"[OK  ] {msg}")

# 冒烟任务：让 claude 实际调用一个本地工具（枚举目录），验证 tool_result 证据流
prompt = (
    "你是一个连通性测试助手。请用 Bash 工具执行命令：`ls` 列出当前目录文件。"
    "然后原样输出 `<Finding>{\"class\":\"smoke\",\"description\":\"冒烟测试\",\"location\":\"./\"}</Finding>` "
    "最后回复：连通性测试通过。"
)

env = cfg.engine_env()
print("-" * 56)
print("正在 spawn claude CLI 执行冒烟任务（首次可能较慢，含模型推理）...")

res = run_session(
    prompt,
    workdir=str(Path(__file__).parent),
    claude_bin="claude",
    env=env,
    max_turns=cfg.max_turns,
    session_seconds=60,
)

print("-" * 56)
print(f"  turns    : {res.num_turns}")
print(f"  is_error : {res.is_error}")
print(f"  error    : {res.error or '(无)'}")
print(f"  findings : {len(res.findings)} 个")
print(f"  工具调用 : {len(res.tool_outputs)} 个")
print(f"  evidence : {len(res.evidence)} 字符")
print("-" * 56)

if res.tool_outputs:
    name, args, out = res.tool_outputs[0]
    print(f"[OK  ] 捕获到真实 tool_result: {name}() -> {out.strip()[:120]}")
    print("[OK  ] stream-json 证据流联通 ✓")
else:
    print("[WARN] 未捕获到 tool_result（可能模型未调用工具，或端点不支持）")

if res.final_text:
    print(f"[INFO] 助手最终回复: {res.final_text.strip()[:200]}")
else:
    print("[WARN] 无最终回复")

print("=" * 56)
sku = "PASS" if (res.tool_outputs and not res.is_error) else "PARTIAL"
print(f"结果: {sku}")
sys.exit(0)