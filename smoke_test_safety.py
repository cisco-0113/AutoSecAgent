"""安全红线冒烟测试 - 破坏性测试硬约束验证。

覆盖：
  1. 三个子代理（web/mobile/iot）在实战模式（ctf_mode=False）下都注入安全红线
  2. 红线内容覆盖：拒绝服务/钓鱼/在线爆破/破坏性写/scope/脱敏 六类
  3. web 工具配方限速（sqlmap --delay/--threads=1；nuclei -rate-limit/-c）
  4. 证据独立性：dry-run 各 finding 证据不再互相串扰
"""
import sys
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from autosec.subagents.base import Delegation
from autosec.subagents.web import WebSubagent
from autosec.subagents.mobile import MobileSubagent
from autosec.subagents.iot import IoTSubagent

ok = 0


def check(name, cond, detail=""):
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


# ── 1) 实战模式注入红线 ──
d = Delegation(target="example.com", surfaces=["web"], ctf_mode=False)
redline_keys = ["禁止拒绝服务", "禁止钓鱼", "禁止在线暴力破解", "禁止破坏性操作",
                "严格授权范围", "数据最小化"]
for name, sub in [("web", WebSubagent()), ("mobile", MobileSubagent()),
                  ("iot", IoTSubagent())]:
    p = sub.build_prompt(d)
    check(f"{name} 实战模式注入安全红线", all(k in p for k in redline_keys),
          f"缺失: {[k for k in redline_keys if k not in p]}")

# ── 2) CTF 模式同样注入（红线与场景无关）──
d_ctf = Delegation(target="ctf.local", surfaces=["web"], ctf_mode=True)
p_ctf = WebSubagent().build_prompt(d_ctf)
check("CTF 模式同样注入红线", all(k in p_ctf for k in redline_keys))

# ── 3) web 工具配方限速 ──
recipes = {}
for doc in yaml.safe_load_all((PROJECT_ROOT / "tools" / "web" / "web-scanners.yaml")
                              .read_text(encoding="utf-8")):
    if doc:
        recipes[doc["name"]] = doc.get("command", "")
check("sqlmap 限速（--delay --threads=1）",
      "--delay" in recipes.get("sqlmap", "") and "--threads=1" in recipes.get("sqlmap", ""))
check("nuclei 限速限并发（-rate-limit -c）",
      "-rate-limit" in recipes.get("nuclei", "") and "-c" in recipes.get("nuclei", ""))

# ── 4) 证据独立性：dry-run 各 finding 证据不再互相串扰 ──
d2 = Delegation(target="demo.apk", surfaces=["mobile"], dry_run=True, ctf_mode=False)
res = MobileSubagent().execute(d2)
for c in res.claims:
    check(f"{c.vuln_class} 证据无串扰",
          "CONNACK" not in c.evidence and "mqtt" not in c.evidence.lower(),
          f"evidence 混入无关内容: {c.evidence[:80]}")

# ── 5) 通配符域名授权匹配（SRC 范围 *.domain 后缀精确匹配）──
from autosec.authorization import Authorization
_a = Authorization(authorized=True, targets=[
    "*.oppo.com", "*.realme.com", "com.oppo.market"])
check("通配符授权对象 authorized=True", _a.authorized)
for tgt, exp in [("shop.oppo.com", True), ("oppo.com", True), ("api.realme.com", True),
                 ("com.oppo.market", True), ("evil-oppo.com", False), ("google.com", False)]:
    check(f"通配符匹配 {tgt} -> {exp}", _a.covers(tgt) == exp,
          f"got {_a.covers(tgt)}")

print(f"\n{'=' * 50}\n安全红线冒烟测试全部通过: {ok} 项")
