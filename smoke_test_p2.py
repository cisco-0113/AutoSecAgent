"""P2 冒烟测试 — Mobile 子代理接入验证。

覆盖：
  1. 分类器: .apk/.ipa/包名 → mobile 攻击面
  2. MobileSubagent dry-run 闭环: 静态类漏洞 oracle 命中 → confirmed；idor-api → probable
  3. Orchestrator 对 apk 目标委派 mobile 子代理（dry-run 全链路）
  4. mock 引擎: 实战模式首轮有 confirmed 即达标（复用 P1.5 收尾逻辑）
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from autosec.classifier import classify
from autosec.config import Config
from autosec.engine import EngineResult, Finding
from autosec.orchestrator import Orchestrator
from autosec.subagents.base import Delegation
from autosec.subagents.mobile import MobileSubagent

ok = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


# ── 1) 分类器识别移动端目标 ──
c1 = classify(r"d:\samples\app-release.apk")
check("classify: .apk → mobile", c1.target_type == "apk" and c1.attack_surfaces == ["mobile"],
      f"got {c1.target_type}/{c1.attack_surfaces}")
c2 = classify(r"d:\samples\AppStore.ipa")
check("classify: .ipa → mobile", c2.target_type == "ipa" and c2.attack_surfaces == ["mobile"])
c3 = classify("com.example.banking")
check("classify: 包名 → mobile", c3.target_type == "app" and "mobile" in c3.attack_surfaces)
c4 = classify("com.tbox.vehicle.app")
check("classify: 车载包名 → iot+mobile", "iot" in c4.attack_surfaces and "mobile" in c4.attack_surfaces,
      f"got {c4.attack_surfaces}")

# ── 2) MobileSubagent dry-run 校验闭环 ──
d = Delegation(target="demo.apk", surfaces=["mobile"], dry_run=True, target_type="apk")
res = MobileSubagent().execute(d)
classes = {c.vuln_class: c.verdict for c in res.claims}
check("dry-run: debuggable → confirmed", classes.get("debuggable") == "confirmed",
      f"got {classes.get('debuggable')}")
check("dry-run: hardcoded-secret → confirmed", classes.get("hardcoded-secret") == "confirmed",
      f"got {classes.get('hardcoded-secret')}")
check("dry-run: idor-api 无差分证据 -> suspected（P4 收紧，须 web_dynamic 差分实锤）",
      classes.get("idor-api") == "suspected", f"got {classes.get('idor-api')}")
check("dry-run: confirmed 数为 2", len(res.confirmed) == 2, f"got {len(res.confirmed)}")

# ── 3) Orchestrator 端到端委派（dry-run + 免授权仅用于本地闭环演示）──
cfg = Config.load()
cfg.auth_required = False
cfg.resolve_paths()
orch = Orchestrator(cfg)
results = orch.run(r"d:\samples\app-release.apk", dry_run=True)
orch.close()
check("orchestrator: 委派了 1 个子代理", len(results) == 1, f"got {len(results)}")
check("orchestrator: 子代理为 mobile", results and results[0].surface == "mobile")
check("orchestrator: 端到端有 confirmed 产出",
      bool(results and len(results[0].confirmed) >= 1))

# ── 4) mock 引擎：实战模式首轮 confirmed 即达标（P1.5 收尾逻辑在 mobile 面复用）──
calls = {"n": 0}

def mock_engine(prompt, workdir, **kw):
    calls["n"] += 1
    er = EngineResult()
    er.num_turns = 8
    er.evidence = '<application android:debuggable="true" android:allowBackup="true">'
    er.findings = [Finding(vuln_class="debuggable", description="可调试",
                           location="AndroidManifest.xml", evidence='android:debuggable="true"',
                           raw='{"class":"debuggable","location":"AndroidManifest.xml"}')]
    er.handoff = ""
    return er

d4 = Delegation(target="demo.apk", surfaces=["mobile"], ctf_mode=False,
                max_turns=60, session_seconds=600, max_continue_rounds=2)
res4 = MobileSubagent().execute(d4, engine=mock_engine)
check("mock: 实战模式首轮 confirmed 即达标不续接", calls["n"] == 1, f"got {calls['n']} 轮")
check("mock: debuggable 过校验门 confirmed",
      any(c.vuln_class == "debuggable" and c.verdict == "confirmed" for c in res4.confirmed))

# ── 5) 提示词完整性：五阶段工作流 + 完成标准 + 知识注入占位符已替换 ──
d5 = Delegation(target="demo.apk", surfaces=["mobile"], ctf_mode=True,
                ctf_skill_dir=tempfile.mkdtemp(prefix="ctf_skills_"),
                knowledge_dir=cfg.knowledge_dir)
prompt = MobileSubagent().build_prompt(d5)
for stage in ("阶段 0", "阶段 1", "阶段 2", "阶段 3", "阶段 4", "阶段 5"):
    check(f"prompt: 含{stage}", stage in prompt)
check("prompt: 含完成标准", "完成标准" in prompt)
check("prompt: 知识占位符已替换", "{knowledge}" not in prompt)
check("prompt: 含场景边界", "场景边界" in prompt)
check("prompt: 含工具降级链", "androguard" in prompt and "降级链" in prompt)

print(f"\n{'=' * 50}\nP2 冒烟测试全部通过: {ok} 项")
