"""P6 质量安全冒烟测试 — 否定门（接 LLM）+ 速率限制/代理池。

运行: python smoke_test_p6.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.engine import EngineResult
from autosec.negation import NegationGate, NegationResult
from autosec.ratelimit import RateLimiter, ProxyPool, RequestThrottle
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


def mock_engine(final_text):
    def _engine(prompt, workdir, **kw):
        return EngineResult(final_text=final_text, num_turns=1)
    return _engine


# ── 1) 否定门：mock LLM 复核 ──
print("\n[1] 否定门接 LLM")
claim = VulnClaim(vuln_class="sqli", statement="注入", location="GET /x",
                  poc="poc", evidence="SQL syntax error")

gate_susp = NegationGate(engine_fn=mock_engine(
    '<Negation>{"verdict":"suspected","reasons":["环境噪声","测试接口"]}</Negation>'))
res = gate_susp.challenge(claim)
check("否定门判 suspected 且 ran=True", res.ran and res.verdict == "suspected", str(res))
check("suspected 触发降级", res.should_downgrade)

gate_conf = NegationGate(engine_fn=mock_engine(
    '<Negation>{"verdict":"confirmed","reasons":["证据扎实"]}</Negation>'))
check("否定门判 confirmed 不降级", not gate_conf.challenge(claim).should_downgrade)

gate_prob = NegationGate(engine_fn=mock_engine(
    '<Negation>{"verdict":"probable","reasons":["存疑"]}</Negation>'))
check("否定门判 probable 降为 probable", gate_prob.challenge(claim).to_probable)

# 无 engine 时安全降级
gate_fail = NegationGate(engine_fn=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no claude")))
res_fail = gate_fail.challenge(claim)
check("否定门调用失败 ran=False 不否决", not res_fail.ran and not res_fail.should_downgrade)

# 无 <Negation> 输出 -> ran=False
gate_empty = NegationGate(engine_fn=mock_engine("没有任何 Negation 标签"))
check("无 Negation 标签 ran=False", not gate_empty.challenge(claim).ran)

# ── 2) 否定门接入 VulnVerifier ──
print("\n[2] VulnVerifier 接入否定门")
v = VulnVerifier(require_poc=True, negator=gate_susp.challenge)
c = VulnClaim(vuln_class="sqli", statement="注入", location="L",
              poc="poc", evidence="SQL syntax error near '1'")
v.verify(c)
check("否定门 suspected 把 confirmed 降为 suspected", c.verdict == "suspected", c.verdict)

v2 = VulnVerifier(require_poc=True, negator=gate_conf.challenge)
c2 = VulnClaim(vuln_class="sqli", statement="注入", location="L",
               poc="poc", evidence="SQL syntax error near '1'")
v2.verify(c2)
check("否定门 confirmed 不改变 confirmed", c2.verdict == "confirmed", c2.verdict)

# 无 negator 时行为不变（向后兼容）
v3 = VulnVerifier(require_poc=True)
c3 = VulnClaim(vuln_class="sqli", statement="注入", location="L",
               poc="poc", evidence="SQL syntax error near '1'")
v3.verify(c3)
check("无 negator 时 confirmed 不变", c3.verdict == "confirmed", c3.verdict)

# ── 3) 速率限制 + 代理池 ──
print("\n[3] 速率限制 + 代理池")
rl = RateLimiter(rps=20)   # 20 req/s，测试快速放行
t0 = time.monotonic()
rl.wait()
check("高速率下 wait 快速返回", time.monotonic() - t0 < 0.5)
check("remaining_seconds 非负", rl.remaining_seconds() >= 0)

pp = ProxyPool(["http://p1:8080", "http://p2:8080", "http://p3:8080"])
got = set()
for _ in range(6):
    got.add(pp.next())
check("代理轮换覆盖 3 个", len(got) == 3, str(got))
pp.mark_bad("http://p1:8080")
check("标记失效后不再返回", all("p1" not in (pp.next() or "") for _ in range(3)))
check("has_available 正确", pp.has_available() and len(pp) == 2)

th = RequestThrottle(rps=100, proxies=["http://p:1"])
check("before_request 返回代理", th.before_request() == "http://p:1")
th.report_failure("http://p:1")
check("report_failure 后代理失效，直连返回 None", th.before_request() is None)

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)
