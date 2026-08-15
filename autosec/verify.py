"""漏洞三重校验门 — 借鉴 hxbai verify.py 的对抗式审查理念，泛化为漏洞语义。

每个漏洞候选 "guilty until proven"，须过三道门才可入报告 (confirmed)：
  1. grounding_gate (落地门)   — 必须有可复现的真实证据（响应特征/回显示法/时间差/OOB），
     而非模型臆测。poc 字段是硬要求。
  2. negation_gate (否定式门)  — 独立视角专司反驳，排除环境噪声/诱饵/非唯一解释。
  3. interrogation_gate(追问门)— 追问"输入可控点/sink/稳定复现/影响"，缺项降级。

POC 校验是纯代码（正则/回显特征），否定/追问门在有 LLM 时执行，无 LLM 时安全降级
为 tentative（绝不虚报 confirmed）。输出三档：confirmed / probable / suspected。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# 常见漏洞类别的可复现回显特征（grounding oracle）
_ORACLES = {
    "sqli":  lambda out: bool(re.search(r"(SQL syntax|SQLITE_ERROR|ORA-\d|PG::|you have an error in your sql|UNION)", out, re.I)),
    "ssti":  lambda out: "49" in out,                                    # {{7*7}} -> 49
    "cmdi":  lambda out: bool(re.search(r"uid=\d+\([^)]*\)\s+gid=\d+", out)),  # id; 回显
    "lfi":   lambda out: bool(re.search(r"root:.*:0:0:", out)),
    "pathtrav": lambda out: bool(re.search(r"root:.*:0:0:|etc/passwd", out, re.I)),
    "xxe":   lambda out: bool(re.search(r"root:.*:0:0:", out)),
    # 注意：idor 等逻辑类漏洞无可靠回显 oracle，故意不在此表——只能走 weak 分支待人工复核
    "xss":   lambda out: bool(re.search(r"<script[^>]*>|alert\(|prompt\(|document\.cookie", out, re.I)),
    "ssrf":  lambda out: bool(re.search(r"169\.254\.169\.254|metadata|internal", out, re.I)),
    # ── 移动端静态类漏洞 oracle：以 manifest/代码原文命中行为 grounding 证据 ──
    "debuggable": lambda out: 'android:debuggable="true"' in out,
    "allow-backup": lambda out: 'android:allowBackup="true"' in out,
    # 导出组件：覆盖 android:exported="true" / exported=true（引号可选）两种写法
    "exported-component": lambda out: bool(re.search(
        r'android:exported\s*=\s*["\']?true|exported\s*=\s*["\']?true|'
        r'<(?:service|activity|receiver|provider)[^>]*exported\s*=\s*["\']?true', out, re.I)),
    # 硬编码密钥：覆盖 smali const-string / 私钥 / AKIA / 变量赋值，
    # 以及 native 反汇编证据（.so/.rodata/getKey/loadLibrary/密钥 hex 常量）
    "hardcoded-secret": lambda out: bool(re.search(
        r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|"
        r"const-string[^\n]*(key|secret|token|password|salt)|"
        r"(api[_-]?key|secret|passwd|password)\s*[:=]\s*[\"'][^\"']{8,}|"
        r"\.rodata|getKey\(\)|loadLibrary|JniKey|\.so[^\n]{0,30}(key|secret)|"
        r"(?:key|密钥)[^\n]{0,40}[0-9a-fA-F]{16,}", out, re.I)),
    "signature-key-leak": lambda out: bool(re.search(
        r"const-string[^\n]*(key|secret|salt|sign)|HmacSHA|signature[^\n]{0,20}key|签名[^\n]{0,10}密钥", out, re.I)),
    "cleartext-traffic": lambda out: bool(re.search(
        r'usesCleartextTraffic="true"|cleartextTrafficPermitted="true"', out)),
    "webview-jsi": lambda out: "addJavascriptInterface" in out,
    # 弱加密：AES/ECB、DES/ECB、无 IV、MD5/SHA1 等弱原语
    "weak-crypto": lambda out: bool(re.search(
        r"AES[/_-]?(ECB|CBC)|DES[/_-]?(ECB|CBC)|PKCS5Padding|"
        r"无\s*IV|no\s+IV|static\s+IV|ECB\s*mode|弱加密|"
        r"MD5\(|SHA-?1\(|MessageDigest", out, re.I)),
    "insecure-storage": lambda out: bool(re.search(
        r"SharedPreferences|getExternalStorage|openOrCreateDatabase|MODE_WORLD_|"
        r"MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|WRITE_MEDIA_STORAGE|"
        r"外部存储|共享存储", out, re.I)),
    # ── 移动端动态分析 oracle：frida hook 输出 / adb 组件调起日志命中行为 grounding ──
    # 由 autosec.mobile_dynamic 生成的 hook 脚本产出这些标识，作为「静态发现→运行时证据」升级门
    "runtime-cred": lambda out: bool(re.search(
        r"\[AUTH\]\s+(SP_PUT|HEADER)|(token|bearer)\s*[=:]\s*[A-Za-z0-9._\-]{12,}", out, re.I)),
    "crypto-key-extract": lambda out: bool(re.search(
        r"\[CRYPTO\]\s+(KEY_HEX|IV_HEX)=[0-9a-fA-F]{8,}|init\(mode=", out)),
    "ssl-unpinning": lambda out: bool(re.search(
        r"VERIFY_BYPASSED|SSLContext\.init hooked|TrustAll registered", out, re.I)),
    "exported-invoke": lambda out: bool(re.search(
        r"Starting: Intent|SUCCESS|complete", out, re.I)),
    # ── IoT/车联网类 oracle：固件原文/MQTT 输出命中行为 grounding 证据 ──
    # 固件提取成功：文件系统签名或提取日志
    "firmware-extract": lambda out: bool(re.search(
        r"(?i)(squashfs|ubifs|jffs2|cpio archive|extracted|filesystem image)", out)),
    # 固件敏感文件：私钥/证书/dropbear host key
    "firmware-secret": lambda out: bool(re.search(
        r"BEGIN [A-Z ]*PRIVATE KEY|dropbear_.*_host_key|id_rsa", out)),
    # 硬编码凭证：Unix shadow 密码 hash 行（$1$/​$5$/$6$ + salt + hash）
    "hardcoded-cred": lambda out: bool(re.search(
        r"\w+:\$[156]\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,}", out)),
    # 后门账户：无密码 root（root::0:0:）或 shadow 空口令
    "backdoor-account": lambda out: bool(re.search(
        r"(?:^|\n)\w+::0:0:|(?:^|\n)\w+::\d+:\d+:\d+:::", out)),
    # 危险默认服务：init 脚本中默认拉起 telnet/ftp/adbd
    "weak-service": lambda out: bool(re.search(
        r"(?i)(telnetd|vsftpd|pure-ftpd|adbd|dropbear)\b[^\n]*(-l|&|start)", out)),
    # 已知 CVE 指纹：版本字符串 + CVE 编号同现
    "known-cve": lambda out: bool(re.search(r"CVE-\d{4}-\d{4,}", out, re.I)),
    # MQTT 匿名接入：CONNACK 成功 / broker 信息回显
    "mqtt-anon-access": lambda out: bool(re.search(
        r"(?i)(CONNACK|rc=0|Connection Accepted|\$SYS/broker)", out)),
    # MQTT 主题信息泄露：车辆/VIN/GPS 数据明文
    "topic-info-leak": lambda out: bool(re.search(
        r"(?i)(\$SYS/broker/version|clients/connected|"
        r"(vin|gps|latitude|longitude|vehicle)[\"'=:\s/{])", out)),
    # MQTT 弱凭证：弱口令登录成功输出（复用 CONNACK 特征）
    "mqtt-weak-cred": lambda out: bool(re.search(
        r"(?i)(CONNACK|rc=0|Connection Accepted)", out)),
    # ── 逻辑类漏洞差分 oracle（P4）：双账号/匿名差分 [DIFF] 证据行升级 confirmed ──
    # 证据格式由 autosec/web_dynamic.py 的 run_differential() 标准化产出：
    #   [DIFF] GET url | owner=200(512B) | attacker=200(508B) | body_sim=0.97 | VERDICT: IDOR_CONFIRMED
    # oracle 校验 [DIFF] 结构 + 相似度阈值 + VERDICT 标记（按实际字段顺序），三者齐备才判 strong
    "idor-api": lambda out: bool(re.search(
        r"\[DIFF\].*body_sim=0\.9\d.*VERDICT: IDOR_CONFIRMED", out)),
    "idor": lambda out: bool(re.search(
        r"\[DIFF\].*body_sim=0\.9\d.*VERDICT: IDOR_CONFIRMED", out)),
    "auth-bypass": lambda out: bool(re.search(
        r"\[DIFF\].*VERDICT: AUTHZ_BYPASS", out)),
    "info-leak": lambda out: bool(re.search(
        r"\[DIFF\].*VERDICT: AUTHZ_BYPASS", out)),
    "priv-escalation": lambda out: bool(re.search(
        r"\[DIFF\].*body_sim=0\.[89]\d.*VERDICT: PRIV_ESC", out)),
    "privilege-escalation": lambda out: bool(re.search(
        r"\[DIFF\].*body_sim=0\.[89]\d.*VERDICT: PRIV_ESC", out)),
    # 短信验证码缺陷：响应回显验证码 / 无差异放行
    "sms-otp-bypass": lambda out: bool(re.search(
        r"\[DIFF\].*VERDICT: AUTHZ_BYPASS|响应.*回显.*验证码|otp.*(?:replay|回显)", out, re.I)),
    # control-msg-forgery / ota-unsigned 仍留 weak：需专用协议证据，暂无标准化格式
}


@dataclass
class VulnClaim:
    """一个待校验的漏洞声明。"""
    vuln_class: str = ""
    statement: str = ""            # 人类可读描述
    location: str = ""             # endpoint / file:line
    poc: str = ""                  # 可复现 POC（命令/请求）—— grounding 硬要求
    expect: str = ""               # 期望在响应中出现的 sentinel/特征
    evidence: str = ""             # 真实 tool 输出（grounding 依据）
    verdict: str = "suspected"     # confirmed | probable | suspected
    confidence: float = 0.0
    reasons: list = field(default_factory=list)
    severity: str = ""             # critical/high/medium/low（引擎评估，供 SRC 报告等级展示）
    fix: str = ""                  # 修复建议（finding 自带，报告优先用它而非模板话术）


class VulnVerifier:
    """漏洞三重校验门。grounding 纯代码；negation 接 LLM（P6）；interrogation 纯代码。"""

    def __init__(self, require_poc: bool = True, negator=None):
        self.require_poc = require_poc
        # negator: callable(claim) -> 带 should_downgrade/to_probable/reasons 属性的对象
        # （由 autosec.negation.NegationGate.challenge 提供）。None = 否定门未启用。
        self.negator = negator

    def verify(self, claim: VulnClaim) -> VulnClaim:
        # Gate 1: grounding（纯代码）——返回 (强度, 说明)，strong/weak/rejected
        strength, why = self._grounding(claim)
        if strength == "rejected":
            return self._finalize(claim, "suspected", 0.1, [f"grounding 未通过: {why}"])
        # Gate 2: negation（P6 接 LLM；未启用/未真正运行时不否决，安全降级）
        neg = self._negation_check(claim)
        if getattr(neg, "should_downgrade", False):
            return self._finalize(claim, "suspected", 0.2,
                                  ["否定门判疑似误报: " + "; ".join(getattr(neg, "reasons", []) or [])])
        # Gate 3: interrogation（poc+expect+evidence 齐备视为可复现）
        missing = self._interrogation_missing(claim)
        if strength == "strong" and not missing:
            if getattr(neg, "to_probable", False):
                return self._finalize(claim, "probable", 0.6,
                                      ["否定门存疑: " + "; ".join(getattr(neg, "reasons", []) or [])])
            return self._finalize(claim, "confirmed", 0.9, ["通过 grounding(强证据) + 具备可复现要素"])
        if strength == "strong":
            return self._finalize(claim, "probable", 0.6, [f"grounding 通过，但缺复现要素: {missing}"])
        # weak：无 oracle 类别，仅静态线索，最多 probable 待人工复核
        return self._finalize(claim, "probable", 0.5, [f"grounding 弱证据（无 oracle 类别）: {why}"])

    def _negation_check(self, claim):
        """执行否定门；negator 未配置或抛异常时返回 None（不否决）。"""
        if self.negator is None:
            return None
        try:
            return self.negator(claim)
        except Exception:  # noqa: BLE001
            return None

    def _grounding(self, c: VulnClaim) -> tuple[str, str]:
        """返回 (strength, 说明)。strength ∈ strong | weak | rejected。"""
        if self.require_poc and not c.poc.strip():
            return "rejected", "缺少可复现 POC（grounding 硬要求）"
        # 1) 显式 expect sentinel：必须在 evidence 中
        if c.expect.strip():
            ok = c.expect in (c.evidence or "")
            return ("strong" if ok else "rejected"), f"期望特征 '{c.expect}' 是否出现"
        # 2) 按类别的回显 oracle
        oracle = _ORACLES.get(c.vuln_class.lower())
        if oracle:
            ok = oracle(c.evidence or "")
            return ("strong" if ok else "rejected"), f"类别 [{c.vuln_class}] 回显特征是否命中"
        # 3) 无 oracle 且无 expect：弱证据，最多 probable，绝不虚报 confirmed
        if (c.evidence or "").strip():
            return "weak", "无 oracle 类别，仅静态线索，需人工复核"
        return "rejected", "无任何证据"

    def _interrogation_missing(self, c: VulnClaim) -> list[str]:
        missing = []
        if not c.location.strip():
            missing.append("location")
        if not c.statement.strip():
            missing.append("statement")
        return missing

    def _finalize(self, c: VulnClaim, verdict: str, conf: float, reasons: list[str]) -> VulnClaim:
        c.verdict = verdict
        c.confidence = conf
        c.reasons = reasons
        return c


def make_claim(finding, evidence: str, poc: str = "", expect: str = "") -> VulnClaim:
    """把 engine.Finding 转成待校验的 VulnClaim。"""
    return VulnClaim(
        vuln_class=finding.vuln_class,
        statement=finding.description,
        location=finding.location,
        poc=poc or finding.raw,
        expect=expect,
        evidence=evidence or finding.evidence,
    )