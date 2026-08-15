"""SRC 漏洞报告模块冒烟测试。

覆盖：
  1. 命名规范：漏洞类型+受影响资产+风险能力（OPPO 平台）
  2. 六大部分详情完整（摘要/资产/复现手册/POC/影响评估/修复建议）
  3. 分平台配置（PLATFORM_PROFILES 含 OPPO，可扩展）
  4. 每个漏洞单独输出报告文件
"""
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT))

from autosec.srcreport import (PLATFORM_PROFILES, build_name, build_report,
                               generate_src_reports, vuln_type_cn, severity_cn)
from autosec.verify import VulnClaim

ok = 0


def check(name, cond, detail=""):
    global ok
    assert cond, f"[FAIL] {name} {detail}"
    ok += 1
    print(f"[PASS] {name}")


# ── 1) 命名规范 ──
check("命名含类型+资产+风险能力（OPPO）",
      "oppo" in PLATFORM_PROFILES and "{type}" in PLATFORM_PROFILES["oppo"]["naming_rule"])

c = VulnClaim(vuln_class="idor-api", statement="改 id 参数可批量获取用户手机号",
              location="GET /api/user/list", verdict="confirmed", confidence=0.9)
name = build_name(c.vuln_class, c.location, c.statement, "oppo")
check("命名示例符合「类型资产，能力」格式",
      "越权" in name and "，可" in name, f"got: {name}")
print(f"  命名示例: {name}")

# native 反汇编证据的硬编码密钥命名
c2 = VulnClaim(vuln_class="hardcoded-secret", statement="密钥从 .so 原样返回，可离线提取解密",
               location="lib/arm64-v8a/libKey.so getKey() @0x2aad0 -> .rodata")
check("hardcoded-secret 命名含类型+密钥资产",
      build_name(c2.vuln_class, c2.location, c2.statement).startswith("硬编码密钥"))

# ── 2) 六大部分 ──
report = build_report(c, target="https://api.example.com", app_version="v1.0",
                      biz_module="用户中心", test_env="Windows + curl")
for section in ("## 一、漏洞摘要", "## 二、受影响资产", "## 三、复现手册",
                "## 四、附件 POC", "## 五、风险影响评估", "## 六、修复建议"):
    check(f"含章节 {section.strip('# ')}", section in report)
check("含测试环境/操作步骤/预期&实际结果子节",
      "测试环境" in report and "操作步骤" in report and "预期结果" in report)

# ── 3) 分平台配置 ──
check("平台配置含 OPPO 及等级", PLATFORM_PROFILES["oppo"]["severity_levels"] == ["严重", "高危", "中危", "低危"])
check("漏洞类型中文映射", vuln_type_cn("idor-api") == "越权访问" and vuln_type_cn("hardcoded-secret") == "硬编码密钥")
check("严重度中文映射", severity_cn("critical") == "严重" and severity_cn("low") == "低危")

# ── 4) 每个漏洞单独报告 ──
claims = [
    VulnClaim(vuln_class="cleartext-traffic", statement="全局明文可被中间人窃听",
              location="AndroidManifest.xml", verdict="confirmed", confidence=0.9,
              poc="usesCleartextTraffic=true", evidence='usesCleartextTraffic="true"'),
    VulnClaim(vuln_class="weak-crypto", statement="AES/ECB 无 IV 可离线还原",
              location="Crypto.smali", verdict="confirmed", confidence=0.9,
              poc="AES/ECB", evidence="AES/ECB/PKCS5Padding 无 IV"),
    VulnClaim(vuln_class="exported-component", statement="服务导出无权限",
              location="ColorosBackupService", verdict="confirmed", confidence=0.9,
              poc="exported=true", evidence="exported=true 无 permission"),
]
with tempfile.TemporaryDirectory() as td:
    files = generate_src_reports(claims, target="com.demo.app", report_dir=td, platform="oppo")
    check("每个漏洞单独一份报告", len(files) == 3, f"got {len(files)}")
    check("报告文件非空", all(Path(p).is_file() and Path(p).stat().st_size > 500 for p in files))
    body = Path(files[1]).read_text(encoding="utf-8")
    check("报告含命名标题与六大部分", body.startswith("# ") and "## 六、修复建议" in body)

print(f"\n{'=' * 50}\nSRC 报告模块冒烟测试全部通过: {ok} 项")
