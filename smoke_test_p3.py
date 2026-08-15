"""P3 冒烟测试 — IoT/车联网子代理接入验证。

覆盖：
  1. 分类器: 固件/MQTT/车载apk/车云域名 → iot 面与正确 route
  2. IoTSubagent dry-run 闭环: 固件/MQTT oracle 命中 → confirmed；车云 VIN 越权 → probable
  3. Orchestrator 端到端委派（固件目标 dry-run；车载 apk 双面委派 iot+mobile）
  4. mock 引擎: 实战模式首轮 confirmed 即达标（P1.5 收尾逻辑在 iot 面复用）
  5. 提示词完整性: 四路线/完成标准/降级链/红线/知识注入
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
from autosec.subagents.iot import IoTSubagent

ok = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


# ── 1) 分类器 IoT 路由 ──
c1 = classify(r"d:\samples\tbox_firmware.bin")
check("classify: .bin → iot/固件逆向", c1.target_type == "firmware"
      and c1.attack_surfaces == ["iot"] and c1.route == "固件逆向",
      f"got {c1.target_type}/{c1.attack_surfaces}/{c1.route}")
c2 = classify("mqtt://tsp-broker.example.com:1883")
check("classify: mqtt → iot/车-云通信", c2.target_type == "mqtt"
      and c2.attack_surfaces == ["iot"] and c2.route == "车-云通信")
c3 = classify(r"d:\samples\tbox_app.apk")
check("classify: 车载 apk → iot+mobile/车载APP逆向", c3.attack_surfaces == ["iot", "mobile"]
      and c3.route == "车载 APP 逆向", f"got {c3.attack_surfaces}/{c3.route}")
c4 = classify("https://tsp.carnet.com")
check("classify: 车云 URL → iot+web/车云平台接口", c4.attack_surfaces == ["iot", "web"]
      and c4.route == "车云平台接口", f"got {c4.attack_surfaces}/{c4.route}")
c5 = classify("ota.vehicle-cloud.cn")
check("classify: 车云域名 → iot+web", "iot" in c5.attack_surfaces and "web" in c5.attack_surfaces,
      f"got {c5.attack_surfaces}")

# ── 2) IoTSubagent dry-run 校验闭环 ──
d = Delegation(target="tbox_firmware.bin", surfaces=["iot"], dry_run=True,
               target_type="firmware", route="固件逆向")
res = IoTSubagent().execute(d)
classes = {c.vuln_class: c.verdict for c in res.claims}
check("dry-run: hardcoded-cred → confirmed（shadow hash oracle 命中）",
      classes.get("hardcoded-cred") == "confirmed", f"got {classes.get('hardcoded-cred')}")
check("dry-run: mqtt-anon-access → confirmed（CONNACK oracle 命中）",
      classes.get("mqtt-anon-access") == "confirmed", f"got {classes.get('mqtt-anon-access')}")
check("dry-run: idor-api 无差分证据 -> suspected（P4 收紧，双 VIN 差分实锤才可升级）",
      classes.get("idor-api") == "suspected", f"got {classes.get('idor-api')}")
check("dry-run: confirmed 数为 2", len(res.confirmed) == 2, f"got {len(res.confirmed)}")

# ── 3) Orchestrator 端到端委派 ──
cfg = Config.load()
cfg.auth_required = False
cfg.resolve_paths()
orch = Orchestrator(cfg)
r1 = orch.run(r"d:\samples\tbox_firmware.bin", dry_run=True)
check("orchestrator: 固件委派 1 个子代理", len(r1) == 1, f"got {len(r1)}")
check("orchestrator: 子代理为 iot", r1 and r1[0].surface == "iot")
r2 = orch.run(r"d:\samples\tbox_app.apk", dry_run=True)
orch.close()
check("orchestrator: 车载 apk 委派 iot+mobile 两面", len(r2) == 2
      and {x.surface for x in r2} == {"iot", "mobile"},
      f"got {[x.surface for x in r2]}")

# ── 4) mock 引擎：实战模式首轮 confirmed 即达标 ──
calls = {"n": 0}

def mock_engine(prompt, workdir, **kw):
    calls["n"] += 1
    er = EngineResult()
    er.num_turns = 8
    er.evidence = "root:$6$k9f3salt$H4sH0cvP3Xk9Z1QvN2bYcXwLmAbCdEf...:0:0:99999:7:::"
    er.findings = [Finding(vuln_class="hardcoded-cred", description="shadow 硬编码 root hash",
                           location="_rootfs/etc/shadow:1", evidence=er.evidence,
                           raw='{"class":"hardcoded-cred"}')]
    return er

d4 = Delegation(target="fw.bin", surfaces=["iot"], ctf_mode=False,
                max_turns=60, session_seconds=600, max_continue_rounds=2)
res4 = IoTSubagent().execute(d4, engine=mock_engine)
check("mock: 实战模式首轮 confirmed 即达标不续接", calls["n"] == 1, f"got {calls['n']} 轮")
check("mock: hardcoded-cred 过校验门 confirmed",
      any(c.vuln_class == "hardcoded-cred" and c.verdict == "confirmed" for c in res4.confirmed))

# ── 5) 提示词完整性 ──
d5 = Delegation(target="fw.bin", surfaces=["iot"], ctf_mode=True, route="固件逆向",
                ctf_skill_dir=tempfile.mkdtemp(prefix="ctf_skills_"),
                knowledge_dir=cfg.knowledge_dir)
prompt = IoTSubagent().build_prompt(d5)
for route in ("路线 A", "路线 B", "路线 C", "路线 D"):
    check(f"prompt: 含{route}", route in prompt)
check("prompt: 含完成标准", "完成标准" in prompt)
check("prompt: 知识占位符已替换", "{knowledge}" not in prompt)
check("prompt: 含场景边界", "场景边界" in prompt)
check("prompt: 含工具降级链", "降级链" in prompt and "strings 兜底" in prompt)
check("prompt: 含车控红线", "禁止向真实车辆发送" in prompt)
check("prompt: MQTT 用纯 Python 客户端", "paho-mqtt" in prompt)
check("prompt: 含 VIN 越权靶点", "VIN 越权" in prompt)

print(f"\n{'=' * 50}\nP3 冒烟测试全部通过: {ok} 项")
