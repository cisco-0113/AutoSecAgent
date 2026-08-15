"""P4 冒烟测试 - Web 动态差分 oracle + 报告生成闭环。

覆盖：
  1. web_dynamic: probe_environment / build_dynamic_plan / 差分判定矩阵
  2. [DIFF] 证据过 verify.py oracle: idor-api / auth-bypass / priv-escalation -> confirmed
  3. NO_DIFF 不得误报（oracle 拒绝 -> suspected）
  4. replay 对不可达目标优雅降级（ERR 行，不抛异常）
  5. report: 跨子代理去重 / 严重度排序 / probable 不混入正式清单 / md+json 落盘
  6. orchestrator dry-run 端到端产出报告文件
  7. web/iot 提示词含差分指引
"""
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from autosec.config import Config
from autosec.engine import Finding
from autosec.orchestrator import Orchestrator
from autosec.report import collect_entries, generate_report, render_markdown
from autosec.subagents.base import SubagentResult
from autosec.verify import VulnClaim, VulnVerifier, make_claim
from autosec.web_dynamic import (ReplayResult, WebDynEnv, build_dynamic_plan,
                                 compare_responses, format_diff_evidence,
                                 probe_environment, replay)

ok = 0


def check(name, cond, detail=""):
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


V = VulnVerifier()


def diff_line(mode_rp, mode_up, verdict, sim, url="/api/order/1001"):
    rp = ReplayResult(label="owner", status=200, body_len=512,
                      body_snippet='{"order":"o1","addr":"victim home"}')
    ru = ReplayResult(label="attacker", status=200, body_len=508,
                      body_snippet='{"order":"o1","addr":"victim home"}')
    return format_diff_evidence("GET", url, rp, ru, verdict, sim, "test")


# ── 1) 环境探测与计划生成 ──
env = probe_environment()
check("probe_environment 返回 WebDynEnv", isinstance(env, WebDynEnv) and bool(env.detail))
print(f"  detail: {env.detail}")

plan = build_dynamic_plan([
    Finding(vuln_class="idor-api", location="GET https://t.example.com/api/order/1001",
            description="订单越权"),
    Finding(vuln_class="sqli", location="POST https://t.example.com/api/login",
            description="注入"),
    Finding(vuln_class="idor-api", location="GET https://t.example.com/api/order/1001?x=1",
            description="同URL去重"),
], target="https://t.example.com")
check("计划含差分项与重放项", any(p.mode == "idor" for p in plan) and any(p.mode == "replay" for p in plan))
check("同 URL 差分项去重", sum(1 for p in plan if p.mode == "idor") == 1)
check("差分项期望证据含 IDOR_CONFIRMED",
      all("IDOR_CONFIRMED" in p.evidence_expected for p in plan if p.mode == "idor"))

# ── 2) 差分判定矩阵（纯逻辑，不依赖网络）──
body_victim = '{"order":"o1","addr":"某市某区1号","phone":"138xxxx"}'
same = ReplayResult(label="owner", status=200, body_len=60, body_snippet=body_victim)
same2 = ReplayResult(label="attacker", status=200, body_len=60, body_snippet=body_victim)
diff_body = ReplayResult(label="attacker", status=403, body_len=20, body_snippet='{"error":"forbidden"}')

v, s, _ = compare_responses(same, same2, mode="idor")
check("同源数据判 IDOR_CONFIRMED", v == "IDOR_CONFIRMED" and s >= 0.90, f"got {v}/{s:.2f}")
v2, _, _ = compare_responses(same, diff_body, mode="idor")
check("属主数据被拒判 NO_DIFF", v2 == "NO_DIFF")

anon_ok = ReplayResult(label="anonymous", status=200, body_len=80, body_snippet='{"secret":"data"}')
v3, _, _ = compare_responses(same, anon_ok, mode="authz")
check("匿名 200 判 AUTHZ_BYPASS", v3 == "AUTHZ_BYPASS")
anon_deny = ReplayResult(label="anonymous", status=401, body_len=0, body_snippet="")
v4, _, _ = compare_responses(same, anon_deny, mode="authz")
check("匿名 401 判 NO_DIFF", v4 == "NO_DIFF")

admin = ReplayResult(label="admin", status=200, body_len=100, body_snippet='{"users":[1,2,3],"role":"admin"}')
lowpriv = ReplayResult(label="user", status=200, body_len=98, body_snippet='{"users":[1,2,3],"role":"admin"}')
v5, _, _ = compare_responses(admin, lowpriv, mode="priv")
check("低权获得管理内容判 PRIV_ESC", v5 == "PRIV_ESC")

# ── 3) [DIFF] 证据过 oracle 升级 confirmed ──
ev_idor = diff_line(same, same2, "IDOR_CONFIRMED", 0.97)
print(f"  样例证据: {ev_idor}")
c = make_claim(Finding(vuln_class="idor-api", location="/api/order/1001",
                       description="订单 IDOR"), ev_idor, poc=ev_idor)
r = V.verify(c)
check("idor-api + [DIFF] IDOR_CONFIRMED -> confirmed", r.verdict == "confirmed", f"got {r.verdict}")

ev_authz = diff_line(same, anon_ok, "AUTHZ_BYPASS", 0.60)
c2 = make_claim(Finding(vuln_class="auth-bypass", location="/api/admin",
                        description="未授权访问"), ev_authz, poc=ev_authz)
r2 = V.verify(c2)
check("auth-bypass + [DIFF] AUTHZ_BYPASS -> confirmed", r2.verdict == "confirmed", f"got {r2.verdict}")

ev_priv = diff_line(admin, lowpriv, "PRIV_ESC", 0.94)
c3 = make_claim(Finding(vuln_class="priv-escalation", location="/admin/users",
                        description="垂直越权"), ev_priv, poc=ev_priv)
r3 = V.verify(c3)
check("priv-escalation + [DIFF] PRIV_ESC -> confirmed", r3.verdict == "confirmed", f"got {r3.verdict}")

# ── 4) NO_DIFF / 无差分不得误报 ──
ev_none = diff_line(same, diff_body, "NO_DIFF", 0.10)
c4 = make_claim(Finding(vuln_class="idor-api", location="/api/order/1001",
                        description="订单 IDOR"), ev_none, poc=ev_none)
r4 = V.verify(c4)
check("NO_DIFF 被 oracle 拒绝 -> suspected", r4.verdict == "suspected", f"got {r4.verdict}")
# 伪造低相似度却标 CONFIRMED 的证据也应被拒（oracle 校验 body_sim>=0.90）
ev_fake = diff_line(same, diff_body, "IDOR_CONFIRMED", 0.55)
c5 = make_claim(Finding(vuln_class="idor-api", location="/api/order/1001",
                        description="伪造"), ev_fake, poc=ev_fake)
r5 = V.verify(c5)
check("低相似度冒充 CONFIRMED 被拒 -> suspected", r5.verdict == "suspected", f"got {r5.verdict}")

# ── 5) replay 对不可达目标优雅降级 ──
rr = replay("http://127.0.0.1:1/x", label="t", timeout=3)
check("replay 不可达目标不抛异常", isinstance(rr, ReplayResult) and (rr.error or rr.status == 0))

# ── 6) 报告：去重 / 排序 / 落盘 ──
def mk_claim(cls, loc, verdict="confirmed", ev="x" * 40):
    c = VulnClaim(vuln_class=cls, statement=f"{cls} 描述", location=loc,
                  poc=ev, evidence=ev, verdict=verdict, confidence=0.9,
                  reasons=["grounding strong"])
    return c

res1 = SubagentResult(surface="mobile")
res1.confirmed = [mk_claim("hardcoded-secret", "smali/com/x/Config.smali:42"),
                  mk_claim("idor-api", "/api/order/1001")]
res2 = SubagentResult(surface="iot")
res2.confirmed = [mk_claim("hardcoded-secret", "smali/com/x/Config.smali:87"),   # 同漏洞不同行号 -> 去重
                  mk_claim("auth-bypass", "/api/admin")]
res2.claims = [mk_claim("debuggable", "AndroidManifest.xml", verdict="probable", ev=""),
               mk_claim("idor-api", "/api/order/1001", verdict="probable")]       # 与 confirmed 重复 -> 不进待复核

confirmed, pending = collect_entries([res1, res2])
check("跨面去重 hardcoded-secret 合并为 1 条",
      sum(1 for e in confirmed if e.vuln_class == "hardcoded-secret") == 1)
check("合并后来源含两攻击面",
      any(set(e.surfaces) == {"mobile", "iot"} for e in confirmed if e.vuln_class == "hardcoded-secret"))
check("confirmed 总数 3（hardcoded-secret 跨面去重后）", len(confirmed) == 3, f"got {len(confirmed)}")
check("critical/high 排在前面", confirmed[0].severity in ("critical", "high"))
check("与 confirmed 重复的 probable 不进待复核",
      not any(e.vuln_class == "idor-api" for e in pending))
check("probable debuggable 进待复核", any(e.vuln_class == "debuggable" for e in pending))

with tempfile.TemporaryDirectory() as td:
    md, js, n_c, n_p = generate_report([res1, res2], "demo.example.com", td,
                                       meta={"surfaces": "mobile, iot", "engine": "test"})
    mdtxt = Path(md).read_text(encoding="utf-8")
    j = json.loads(Path(js).read_text(encoding="utf-8"))
    check("md/json 落盘且可解析", Path(md).is_file() and j["target"] == "demo.example.com")
    check("md 含 POC/修复/证据章节", all(k in mdtxt for k in ("复现步骤", "修复建议", "证据")))
    check("md probable 不混入正式清单章节",
          "## 二、待复核" in mdtxt and mdtxt.index("## 一、已确认漏洞") < mdtxt.index("## 二、待复核"))
    check("json 含 confirmed 与 pending_review",
          len(j["confirmed"]) == 3 and len(j["pending_review"]) == 1)

# ── 7) orchestrator dry-run 端到端产出报告（临时目录，避免测试产物污染正式 reports/）──
with tempfile.TemporaryDirectory() as td:
    cfg = Config.load()
    cfg.auth_required = False
    cfg.resolve_paths()
    cfg.report_dir = td
    orch = Orchestrator(cfg)
    results = orch.run(r"d:\samples\app-release.apk", dry_run=True)
    orch.close()
    reports = sorted(Path(cfg.report_dir).glob("*app-release.apk_report.*"))
    check("orchestrator 端到端生成报告文件", len(reports) >= 2, f"got {len(reports)}")
    if reports:
        tail = reports[-1].read_text(encoding="utf-8")[:200]
        check("报告内容非空且含标题", "AutoSecAgent 漏洞报告" in tail)

# ── 8) 提示词含差分指引 ──
from autosec.subagents.iot import IoTSubagent
from autosec.subagents.web import WebSubagent
wp = WebSubagent().build_prompt.__self__._base_prompt(
    __import__("autosec.subagents.base", fromlist=["Delegation"]).Delegation(
        target="t.example.com", surfaces=["web"]))
check("web 提示词含差分指引", "run_differential" in wp and "[DIFF]" in wp)

print(f"\n{'=' * 50}\nP4 冒烟测试全部通过: {ok} 项")
