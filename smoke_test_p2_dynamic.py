"""P2 动态分析工作流冒烟测试 — 静态发现 → 动态验证计划 → 证据升级。

覆盖：
  1. probe_environment 不抛异常，返回可用性快照
  2. frida_script_for 按漏洞类别生成 hook 脚本（含占位符替换）
  3. build_dynamic_plan 把静态 Finding 转成有优先级计划（去重同脚本）
  4. write_hooks 把脚本落盘
  5. 动态证据过 verify.py oracle：probable → confirmed 升级
"""
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from autosec.engine import Finding
from autosec.mobile_dynamic import (DynEnv, probe_environment, frida_script_for,
                                    build_dynamic_plan, write_hooks, render_plan)
from autosec.verify import make_claim, VulnVerifier

ok = 0


def check(name, cond, detail=""):
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


# ── 1) 环境探测（本机无设备也应正常返回，不抛异常）──
env = probe_environment()
check("probe_environment 返回 DynEnv", isinstance(env, DynEnv))
check("probe 不抛异常且 detail 非空", bool(env.detail))
print(f"  detail: {env.detail}")

# ── 2) frida 脚本生成 ──
s = frida_script_for("crypto-key-extract", pkg="com.bank.app", fn="AESManager")
check("crypto hook 生成且无占位符残留",
      "KEY_HEX" in s and "{PKG}" not in s and "{FN}" not in s)
check("weak-crypto 复用 crypto 模板", "KEY_HEX" in frida_script_for("weak-crypto"))
check("ssl-unpinning 生成", "VERIFY_BYPASSED" in frida_script_for("ssl-unpinning"))
check("runtime-cred 生成", "[AUTH]" in frida_script_for("login-token"))
check("未知类别返回空串", frida_script_for("whatever") == "")

# ── 3) 静态发现 → 动态计划 ──
findings = [
    Finding(vuln_class="hardcoded-secret", location="com/bank/Config.smali:42",
            description="硬编码密钥", evidence="const-string"),
    Finding(vuln_class="exported-component", location="com.bank.app.SplashActivity",
            description="导出组件", evidence='android:exported="true"'),
    Finding(vuln_class="weak-crypto", location="AESManager",
            description="弱加密", evidence="AES/ECB"),
    Finding(vuln_class="hardcoded-secret", location="com/bank/Other.smali:9",
            description="重复类别", evidence="const-string"),
]
plan = build_dynamic_plan(findings, pkg="com.bank.app")
check("计划生成非空", len(plan) >= 2)
check("同类别脚本去重（hardcoded-secret 只出一条）",
      sum(1 for p in plan if p.target == "hardcoded-secret") == 1)
check("导出组件走 adb am start 命令", any(
    p.command.startswith("adb shell am start") for p in plan))
check("crypto 类有脚本且期望证据 KEY_HEX", any(
    "KEY_HEX=" == p.evidence_expected for p in plan))

# ── 4) 脚本落盘 ──
with tempfile.TemporaryDirectory() as td:
    written = write_hooks(plan, td)
    check("hook 脚本落盘且为有效 JS", len(written) >= 1 and all(Path(p).is_file() for p in written)
          and "Java.perform" in Path(written[0]).read_text(encoding="utf-8"))

# ── 5) 动态证据过 oracle：probable → confirmed 升级 ──
# 模拟 agent 跑 frida 后拿到的运行时证据
dyn_evidence = "java.lang.System.load...\n[CRYPTO] init mode=1 key=key\n[CRYPTO] KEY_HEX=0123456789abcdef0123456789abcdef\n"
claim = make_claim(Finding(vuln_class="crypto-key-extract", location="AESManager",
                           description="弱加密", evidence=""), dyn_evidence, poc=dyn_evidence)
res = VulnVerifier().verify(claim)
check("动态证据 KEY_HEX 命中 oracle 判 confirmed",
      res.verdict == "confirmed", f"got {res.verdict}")
claim2 = make_claim(Finding(vuln_class="runtime-cred", location="LoginActivity",
                            description="令牌泄露", evidence=""),
                    "[AUTH] SP_PUT token=eyJhbGciOiJIUzI1NiJ9.abc.xyz",
                    poc="[AUTH] SP_PUT token=eyJhbGciOiJIUzI1NiJ9.abc.xyz")
res2 = VulnVerifier().verify(claim2)
check("动态证据 SP_PUT token 判 confirmed", res2.verdict == "confirmed", f"got {res2.verdict}")

# ── 6) 计划渲染成可执行文本 ──
txt = render_plan(plan, env)
check("render_plan 含环境结论与命令", "动态环境" in txt and "frida" in txt)

# ── 7) 跨 finding 引导：UI 驱动造数据 ──
plan_ui = build_dynamic_plan([Finding(vuln_class="insecure-storage",
                                      location="AndroidManifest.xml",
                                      description="共享存储")], pkg="com.demo")
check("存储类触发 ui-drive-data 引导",
      any(p.target == "ui-drive-data" for p in plan_ui))
check("ui-drive-data 含 uiautomator 命令", any(
    p.target == "ui-drive-data" and "uiautomator" in p.command for p in plan_ui))

# ── 8) 跨 finding 引导：离线解密验证 ──
plan_dec = build_dynamic_plan([
    Finding(vuln_class="weak-crypto", location="Crypto.smali", description="弱加密"),
    Finding(vuln_class="hardcoded-secret", location="libKey.so", description="硬编码密钥"),
], pkg="com.demo")
check("加密组合触发 offline-decrypt 引导",
      any(p.target == "offline-decrypt" for p in plan_dec))
check("offline-decrypt 含离线解密命令", any(
    p.target == "offline-decrypt" and "offline_decrypt" in p.command for p in plan_dec))

# ── 9) adb 探测覆盖项目内 platform-tools ──
from autosec.mobile_dynamic import _find_adb
check("_find_adb 能定位可执行文件（PATH 或项目内）", bool(_find_adb()))

print(f"\n{'=' * 50}\nP2 动态工作流冒烟测试全部通过: {ok} 项")