"""P1 里程碑离线自测 — 验证执行引擎/工具治理/校验门闭环。

运行: .venv\\Scripts\\python.exe smoke_test_p1.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.engine import extract_findings, extract_handoff, Finding
from autosec.toolrun import ToolRunner, ToolRecipe
from autosec.verify import VulnClaim, VulnVerifier

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


# ---- 1. 执行引擎: finding 解析 ----
print("\n[1] 执行引擎 finding/交互解析")
sample = (
    "侦察完成。发现注入点。\n"
    '<Finding>{"class":"sqli","description":"id 参数注入","location":"GET /api/item?id=1","confidence":"probable","evidence":"SQL error"}</Finding>\n'
    '<Finding>{"class":"ssti","description":"模板注入","location":"POST /greet"}</Finding>\n'
    "<Handoff>下一轮深挖认证接口</Handoff>"
)
finds = extract_findings(sample)
check("解析出 2 个 finding", len(finds) == 2, f"got {len(finds)}")
check("finding 结构化字段完整", finds[0].vuln_class == "sqli" and "注入" in finds[0].description)
check("handoff 提取", extract_handoff(sample) == "下一轮深挖认证接口")

# ---- 2. 工具治理: 配方加载 + spill ----
print("\n[2] 工具治理")
runner = ToolRunner(max_output_chars=100, spill_dir="data/spill")
recipes = runner.load_recipes("tools/web", surface="web")
check("加载 web 配方 3 份", len(recipes) == 3, f"got {len(recipes)}")
check("spill 治理: 超长输出截断", runner.run(["cmd", "/c", "echo", "x" * 500]).truncated)
check("spill 治理: 落盘文件生成",
      any(Path("data/spill").glob("spill-*.txt")))

# ---- 3. 校验门: 分级 ----
print("\n[3] 三重校验门分级")
v = VulnVerifier(require_poc=True)
c1 = VulnClaim(vuln_class="sqli", statement="注入", location="L",
               poc="sqli poc", evidence="SQL syntax error near '1'")
v.verify(c1)
check("sqli 强证据 -> confirmed", c1.verdict == "confirmed", c1.verdict)

c2 = VulnClaim(vuln_class="ssti", statement="注入", location="L",
               poc="poc", evidence="Hello 49")
v.verify(c2)
check("ssti 强证据 -> confirmed", c2.verdict == "confirmed", c2.verdict)

c3 = VulnClaim(vuln_class="idor", statement="越权", location="L",
               poc="poc", evidence="改 id 返回 200 含他人数据")
v.verify(c3)
# P4 起 idor 有差分 oracle：纯描述证据不再走 weak probable，直接拒绝（防叙事型虚报）
check("idor 无[DIFF]证据 -> suspected（P4 收紧，须差分实锤）", c3.verdict == "suspected", c3.verdict)

c4 = VulnClaim(vuln_class="sqli", statement="注入", location="L",
               poc="", evidence="SQL error")
v.verify(c4)
check("缺 POC -> suspected", c4.verdict == "suspected", c4.verdict)

c5 = VulnClaim(vuln_class="sqli", statement="注入", location="L",
               poc="poc", evidence="无任何特征")
v.verify(c5)
check("证据不匹配 -> suspected", c5.verdict == "suspected", c5.verdict)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)