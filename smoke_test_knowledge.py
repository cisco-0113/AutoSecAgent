"""自学习知识库冒烟测试 — 信号驱动的经验提取。

覆盖 learn_from_result 的信号识别：
  1. finding -> success 经验（漏洞本身是最硬经验）
  2. handoff -> 失败经验（遗留状态）
  3. 组合链检测：≥2 个可组合类别 -> 提示串成攻击链
  4. 噪声过滤：纯信息获取 tool / 脚本噪声 / 纯 URL 浏览不记录
  5. 技术动作命令：命令执行 + 输出非空 + 命中动作信号才记录
  6. 种子经验渲染：组合链 + 备份加密链永久回灌

运行: python smoke_test_knowledge.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.engine import Finding
from autosec.knowledge import learn_from_result, SelfLearningStore

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def f(cls, loc, desc=""):
    return Finding(vuln_class=cls, location=loc, description=desc or f"{cls} 描述")


def entries_of(tool_outputs=None, findings=None, handoff="", evidence=""):
    return learn_from_result("mobile", "com.demo", findings or [], handoff,
                             evidence, tool_outputs or [])


print("\n[1] finding / handoff 基础经验")
res = entries_of(findings=[f("hardcoded-secret", "libKey.so")], handoff="下一步深挖加密链")
check("finding 生成 success 经验",
      any(e.success and e.source == "self-learned" for e in res))
check("handoff 生成失败经验",
      any((not e.success) and e.tags == ["handoff"] for e in res))

print("\n[2] 组合链检测")
res = entries_of(findings=[
    f("hardcoded-secret", "libKey.so"),
    f("weak-crypto", "Crypto.smali"),
    f("insecure-storage", "AndroidManifest.xml"),
])
check("≥2 个可组合类别触发串链提示",
      any("chain-hint" in e.tags for e in res))
res_single = entries_of(findings=[f("hardcoded-secret", "libKey.so")])
check("单个可组合类别不触发串链提示",
      not any("chain-hint" in e.tags for e in res_single))

print("\n[3] 噪声过滤（应无 tool-trace 记录）")
noise = [
    ("WebSearch", {"query": "oppo backup decrypt"}, "搜索结果..."),
    ("WebFetch", {"url": "https://blog.flanker017.me"}, "页面内容..."),
    ("Read", {"file_path": "x.smali"}, "const-string..."),
    ("Bash", {"command": "Write-Host 'hello'; echo test"}, "hello"),
    ("PowerShell", {"command": "$u='https://www.reddit.com/r/Oppo/search'"}, ""),
    ("Bash", {"command": "echo hello world"}, "hello"),
]
res = entries_of(tool_outputs=noise)
check("纯信息获取/脚本噪声/纯URL 全部不记为 tool-trace",
      not any(e.source == "tool-trace" for e in res))

print("\n[4] 技术动作命令记录")
actions = [
    ("Bash", {"command": "frida -U -f com.demo -l hook.js --no-pause"}, "[CRYPTO] KEY_HEX=..." ),
    ("Bash", {"command": "adb shell am startservice -a com.mov.action.backup"}, "Starting: Intent"),
    ("Bash", {"command": "python decrypt.py --db backup_config_new.db"}, "BEGIN:VCARD"),
    ("Bash", {"command": "curl -X POST https://api.demo.com/login -d 'u=a&p=b'"}, "200 OK"),
]
res = entries_of(tool_outputs=actions)
traces = [e for e in res if e.source == "tool-trace"]
check("技术动作命令全部记录", len(traces) == 4, f"got {len(traces)}")
check("记录均标记 success=False（尝试过）", all(not e.success for e in traces))

print("\n[5] 无产出兜底")
res = entries_of(tool_outputs=[("Bash", {"command": "echo hi"}, "")], evidence="recon evidence")
check("无任何产出时记录一条侦察兜底",
      any(e.tags == ["recon"] for e in res))

print("\n[6] 种子经验渲染")
txt = SelfLearningStore().render(category="mobile")
check("组合链方法论种子经验已注入", "组合" in txt)
check("备份加密链种子经验已注入", "备份" in txt and "密钥" in txt)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)
