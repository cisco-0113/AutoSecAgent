"""SRC 漏洞报告子模块 — 按平台规范生成单个漏洞的独立交付报告。

解决「挖到却交不出」的最后一公里：把校验门产出的 VulnClaim 转成符合各 SRC
平台提交规范的漏洞报告。核心能力：
  1. 分平台配置（PLATFORM_PROFILES）：不同 SRC 平台的命名规则、等级、必填字段
     各不相同，本模块集中登记，新增平台只需加一个 profile。
  2. 命名规范：按平台 naming_rule 生成漏洞名称（OPPO = 漏洞类型+受影响资产+风险能力）。
  3. 六大部分详情：漏洞摘要 / 受影响资产 / 复现手册 / 附件POC / 风险影响评估 / 修复建议。
  4. 每个漏洞单独输出一个报告文件（便于逐个提交 SRC 平台）。

命名示例（OPPO SRC）：未授权访问list接口，可批量获取用户手机号
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── 漏洞类型 -> 中文名（用于命名「漏洞类型」段）──────────────────────────────
VULN_TYPE_CN = {
    "sqli": "SQL注入", "ssti": "模板注入", "cmdi": "命令注入", "ssrf": "SSRF服务端请求伪造",
    "xxe": "XXE外部实体注入", "xss": "跨站脚本XSS", "lfi": "本地文件包含", "pathtrav": "路径穿越",
    "idor": "越权访问", "idor-api": "越权访问", "auth-bypass": "认证绕过", "priv-escalation": "权限提升",
    "privilege-escalation": "权限提升", "info-leak": "信息泄露", "rce": "远程代码执行",
    "cleartext-traffic": "明文传输", "hardcoded-secret": "硬编码密钥", "weak-crypto": "弱加密算法",
    "exported-component": "组件未授权导出", "insecure-storage": "敏感数据不安全存储",
    "debuggable": "应用调试开启", "allow-backup": "备份未关闭", "signature-key-leak": "签名密钥泄露",
    "webview-jsi": "WebView JS接口注入", "weak-cert-validation": "证书校验缺失", "ssl-unpinning": "证书校验缺失",
    "hardcoded-cred": "硬编码凭证", "backdoor-account": "后门账户", "default-cred": "默认凭证",
    "mqtt-anon-access": "MQTT匿名接入", "mqtt-weak-cred": "MQTT弱凭证", "topic-info-leak": "主题信息泄露",
    "control-msg-forgery": "控制指令伪造", "sms-otp-bypass": "短信验证码绕过", "ota-unsigned": "OTA未签名",
    "known-cve": "已知CVE漏洞", "firmware-secret": "固件敏感信息", "weak-service": "危险服务",
    "runtime-cred": "运行时凭证泄露", "crypto-key-extract": "加密密钥可提取",
}

# ── 漏洞类型 -> 默认风险能力（命名「风险能力」段的兜底，无 description 时用）──
_DEFAULT_CAPABILITY = {
    "cleartext-traffic": "可被中间人窃听/篡改通信内容",
    "hardcoded-secret": "可离线提取密钥解密敏感数据",
    "weak-crypto": "加密可被离线破解还原明文",
    "exported-component": "可被任意应用未授权调用",
    "insecure-storage": "可导致敏感数据被越权读取",
    "idor-api": "可越权访问他人数据",
    "idor": "可越权访问他人数据",
    "auth-bypass": "可未授权访问受保护功能",
    "info-leak": "可导致敏感信息泄露",
    "sqli": "可读取/篡改数据库数据",
    "rce": "可远程执行任意代码",
}

# ── 漏洞类型 -> 默认资产名（命名「受影响资产」段的兜底，location 提炼失败时用）──
_DEFAULT_ASSET = {
    "cleartext-traffic": "应用网络通信",
    "hardcoded-secret": "应用加密密钥",
    "weak-crypto": "本地加密逻辑",
    "exported-component": "导出组件",
    "insecure-storage": "本地数据存储",
    "idor-api": "数据接口",
    "auth-bypass": "受保护接口",
    "info-leak": "数据接口",
}

# ── 严重度 -> 中文等级（SRC 平台通用等级）───────────────────────────────────
SEVERITY_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


# ── 分平台配置：不同 SRC 平台的报告要求集中登记 ─────────────────────────────
# 命名规则里的 {type}/{asset}/{capability} 会被 build_name() 替换。
PLATFORM_PROFILES = {
    "oppo": {
        "name": "OPPO SRC",
        # 命名规则（来自 OPPO 提交表单）：漏洞类型+受影响资产+风险能力
        "naming_rule": "{type}{asset}，{capability}",
        "naming_example": "未授权访问list接口，可批量获取用户手机号",
        "severity_levels": ["严重", "高危", "中危", "低危"],
        "required_sections": ["漏洞摘要", "受影响资产", "复现手册", "附件POC", "风险影响评估", "修复建议"],
        "notes": "自有业务/测试环境/第三方业务分类；核心业务按重要程度评估",
    },
    # 预留：其他平台接入时在此追加 profile（如腾讯 TSRC、阿里 ASRC、补天、漏洞盒子）
    # "tsrc": { "name": "腾讯 TSRC", "naming_rule": "...", ... },
}


def vuln_type_cn(cls: str) -> str:
    return VULN_TYPE_CN.get((cls or "").lower(), (cls or "漏洞"))


def severity_cn(sev: str) -> str:
    return SEVERITY_CN.get((sev or "").lower(), "中危")


def _extract_capability(desc: str, cls: str) -> str:
    """从描述中提取「风险能力」短句：描述短语 > 类型默认映射 > 动词短语回退。"""
    desc = (desc or "").strip()
    m = re.search(r"(可[^，。；;,，\s]{5,18})", desc)
    if m:
        return m.group(1)
    default = _DEFAULT_CAPABILITY.get((cls or "").lower())
    if default:
        return default
    m = re.search(r"(导致|造成|泄露|解密|还原|读取|篡改|执行|获取)[^，。；;,，\s]{1,14}", desc)
    if m:
        return m.group(0)
    return "影响业务安全"


def _short_asset(location: str, cls: str) -> str:
    """从 location 提炼简短「受影响资产」用于命名。

    优先级：组件类名（仅类名，不含包名）> 关键模块词 > 默认资产映射。
    """
    loc = (location or "").strip()
    # 1) 优先提取组件类名（仅取类名，去掉 com.xxx 包名前缀）
    m = re.search(r"([A-Za-z_]\w*(?:Service|Activity|Receiver|Provider|Manager|Client))\b", loc)
    if m:
        return m.group(1)
    # 2) 关键模块词
    m = re.search(r"(?i)(backuprestore|backup|restore|crypto|encrypt|decrypt|network[_-]?security|"
                  r"storage|kms|cloud|clone|wallet|account|browser|market|findmyphone|speechassist)", loc)
    if m:
        w = m.group(1).lower()
        cn = {"backuprestore": "备份恢复", "backup": "备份", "restore": "恢复", "crypto": "加密",
              "encrypt": "加密", "decrypt": "解密", "storage": "存储", "kms": "密钥管理", "cloud": "云服务",
              "clone": "手机克隆", "wallet": "钱包", "account": "账号", "browser": "浏览器", "market": "软件商店",
              "findmyphone": "查找手机", "speechassist": "语音助手"}.get(w)
        if cn:
            return cn
    # 3) 兜底默认资产
    return _DEFAULT_ASSET.get((cls or "").lower(), "相关接口/组件")


def build_name(cls: str, location: str, description: str, platform: str = "oppo") -> str:
    """按平台命名规则生成漏洞名称。

    OPPO：{漏洞类型}+{受影响资产}+{风险能力}，示例「未授权访问list接口，可批量获取用户手机号」。
    资产词已包含在类型词中（如「存储」⊂「敏感数据不安全存储」）时省略资产段，避免「存储存储」类重复。
    """
    profile = PLATFORM_PROFILES.get(platform, PLATFORM_PROFILES["oppo"])
    rule = profile["naming_rule"]
    t = vuln_type_cn(cls)
    asset = _short_asset(location, cls)
    if asset and asset in t:
        asset = ""
    return (rule
            .replace("{type}", t)
            .replace("{asset}", asset)
            .replace("{capability}", _extract_capability(description, cls)))


# ── 六大部分漏洞报告渲染 ──────────────────────────────────────────────────────
def _sanitize_claim(claim):
    """修复畸形 claim：statement 是 finding 原始 JSON 串时，解出 class/description/location 回填。

    JSON 可能被上游截断（非法 JSON），故优先 json.loads、失败则退回正则逐字段提取。
    """
    s = (claim.statement or "").strip()
    if not s.startswith("{"):
        return claim
    obj = None
    try:
        obj = json.loads(s)
    except Exception:  # noqa: BLE001
        pass
    if not isinstance(obj, dict):
        obj = {}
        # 键名可能缺前引号（上游拼接错误，如 ,location":"...），故 " 用 ? 容错
        for key, pat in (("class", r'"?class"?\s*:\s*"([^"]+)"'),
                         ("description", r'"?description"?\s*:\s*"([^"]+)"'),
                         ("location", r'"?location"?\s*:\s*"([^"]+)"')):
            m = re.search(pat, s)
            if m:
                obj[key] = m.group(1)
    if not obj.get("description"):
        return claim
    if not (claim.vuln_class or "").strip() and obj.get("class"):
        claim.vuln_class = str(obj["class"])
    claim.statement = str(obj["description"])
    if not (claim.location or "").strip() and obj.get("location"):
        claim.location = str(obj["location"])
    # poc 同为 finding JSON 串时，取出其中 evidence 字段的文字描述充当复现说明
    poc = (claim.poc or "").strip()
    if poc.startswith("{"):
        m = re.search(r'"?evidence"?\s*:\s*"([^"]+)"', poc)
        if m:
            claim.poc = m.group(1)
    return claim


def build_report(claim, target: str = "", platform: str = "oppo",
                 app_version: str = "", biz_module: str = "", test_env: str = "",
                 account_note: str = "") -> str:
    """把单个 VulnClaim 渲染成符合平台规范的漏洞报告（六大部分）。

    claim: VulnClaim（含 vuln_class/statement/location/poc/evidence/verdict/confidence/reasons）
    target / app_version / biz_module / test_env / account_note：受影响资产与复现环境的补充信息，
        优先由调用方从运行上下文注入，缺省用 claim 现有字段兜底。
    """
    profile = PLATFORM_PROFILES.get(platform, PLATFORM_PROFILES["oppo"])
    claim = _sanitize_claim(claim)
    name = build_name(claim.vuln_class, claim.location, claim.statement, platform)
    sev = severity_cn(getattr(claim, "severity", "") or "medium")
    cls_cn = vuln_type_cn(claim.vuln_class)
    loc = claim.location or "（待补充）"
    desc = claim.statement or claim.poc or "（待补充）"
    poc_full = (claim.poc or "").strip() or "（见下方证据）"
    poc = poc_full[:3000] + ("\n…（POC 过长已截断，完整内容见原始审计记录）"
                             if len(poc_full) > 3000 else "")
    evidence = (claim.evidence or "").strip() or "（无）"
    fix = (getattr(claim, "fix", "") or "").strip()
    if not fix or "行业标准实践" in fix:   # 空或套话模板时优先类型专属建议
        fix = _fix_advice(claim.vuln_class)

    lines = [
        f"# {name}",
        "",
        f"> 平台: {profile['name']}  |  漏洞类型: {cls_cn}  |  等级: {sev}",
        f"> 验证状态: {claim.verdict}（置信度 {claim.confidence:.0%}）",
        "",
        "---",
        "",
        "## 一、漏洞摘要",
        "",
        desc,
        "",
        "## 二、受影响资产",
        "",
        f"- **漏洞位置**: `{loc}`",
        f"- **应用/版本**: {app_version or '（待补充）'}" if app_version else "- **应用/版本**: （待补充）",
        f"- **所属业务模块**: {biz_module or '（待补充）'}",
        f"- **完整 URL/API 端点**: {target or '（待补充）'}",
        "",
        "## 三、复现手册",
        "",
        "### 1. 测试环境",
        f"- 操作系统: {test_env or '（待补充）'}",
        f"- 测试工具及版本: （待补充，如 androguard 4.1.4 / apktool 2.9.3 / frida 17）",
        f"- 测试账号及权限: {account_note or '（待补充）'}",
        "",
        "### 2. 操作步骤",
        "（审核人员仅凭此部分即可独立复现；以下为已收集证据对应的复现路径）",
        poc,
        "",
        "### 3. 预期结果 & 实际结果",
        f"- **预期结果**: 系统应按正常安全逻辑拒绝/加密/鉴权。",
        f"- **实际结果**: {desc}",
        "",
        "## 四、附件 POC",
        "",
        "```",
        poc_full[:2000],
        "```",
        "",
        "**证据（真实工具输出）**",
        "```",
        evidence[:2000],
        "```",
        "",
        "> 打包 ZIP 时需放置 README.txt 说明各文件对应的步骤编号。",
        "",
        "## 五、风险影响评估",
        "",
        f"- **可能的攻击行为**: {_extract_capability(desc, claim.vuln_class)}",
        f"- **影响范围**: {loc}",
        "- **安全后果（机密性/完整性/可用性）**: " + _impact_cia(claim.vuln_class),
        "",
        "## 六、修复建议",
        "",
        fix,
        "",
        "---",
        f"_由 AutoSecAgent 自动生成 · {time.strftime('%Y-%m-%d %H:%M:%S')}_",
    ]
    return "\n".join(lines)


def _impact_cia(cls: str) -> str:
    """按漏洞类别给出机密性/完整性/可用性影响描述。"""
    c = (cls or "").lower()
    if c in ("hardcoded-secret", "weak-crypto", "signature-key-leak", "crypto-key-extract", "runtime-cred"):
        return "机密性：敏感数据可被离线解密/还原（高）；完整性：加密保护形同虚设；可用性：无直接影响。"
    if c in ("cleartext-traffic", "weak-cert-validation", "ssl-unpinning"):
        return "机密性：通信内容可被中间人窃听（高）；完整性：流量可被篡改注入；可用性：无直接影响。"
    if c in ("exported-component", "insecure-storage", "allow-backup", "debuggable"):
        return "机密性：本地数据/功能可被越权访问（中高）；完整性：可被写入/篡改；可用性：可被滥用触发拒绝。"
    if c in ("idor", "idor-api", "auth-bypass", "priv-escalation", "privilege-escalation"):
        return "机密性：越权读取他人数据（高）；完整性：越权篡改；可用性：取决于接口敏感度。"
    if c in ("sqli", "rce", "cmdi", "ssti"):
        return "机密性：数据库/系统数据泄露（高）；完整性：数据被篡改；可用性：可致服务不可用。"
    return "机密性/完整性/可用性：视具体利用路径评估，建议按最高可能影响定级。"


def _fix_advice(cls: str) -> str:
    """原理性修复思路（避免临时规避）。"""
    c = (cls or "").lower()
    adv = {
        "hardcoded-secret": "密钥不得随包分发，应改由服务端下发 + 设备级安全存储（Keystore/TrustZone/白盒），并建立密钥轮换机制。",
        "weak-crypto": "替换为 AEAD 加密原语（AES-GCM / ChaCha20-Poly1305），随机 IV + 认证标签，禁止 ECB 与无认证模式。",
        "cleartext-traffic": "全局关闭明文（usesCleartextTraffic=false），TLS 强制 + 证书固定（pinning），敏感域名单独收紧 trust-anchor。",
        "exported-component": "非必要组件显式 exported=false；必须导出的加 android:permission 签名级校验，运行时校验调用方身份。",
        "insecure-storage": "敏感数据迁入加密存储（EncryptedSharedPreferences/Keystore），不落共享外部存储。",
        "allow-backup": "android:allowBackup=false，或备份规则排除敏感数据。",
        "debuggable": "release 构建移除 android:debuggable，回归发布流水线阻断 debuggable 包上线。",
        "idor-api": "服务端按会话身份做资源属主校验（owner check），禁止仅凭前端传 ID 取数。",
        "idor": "同 idor-api：接口层做属主校验，列表/详情/导出全链路覆盖。",
        "auth-bypass": "受保护路由必须先过身份校验中间件，默认拒绝未授权访问。",
        "priv-escalation": "服务端按角色白名单校验管理接口，前端隐藏不等于鉴权。",
        "sqli": "参数化查询/预编译语句，禁止字符串拼接 SQL。",
        "rce": "命令参数白名单枚举，禁止用户输入直接拼入 shell。",
        "info-leak": "接口加身份鉴权与属主校验，敏感字段按角色脱敏。",
    }
    return adv.get(c, "按该类漏洞的行业标准实践从根源加固，并结合上下文做回归验证。")


# ── 批量：每个漏洞单独输出一份报告文件 ───────────────────────────────────────
def generate_src_reports(claims: list, target: str = "", report_dir: str | Path = "reports",
                         platform: str = "oppo", meta: dict | None = None) -> list[str]:
    """为每个漏洞单独生成一份符合平台规范的报告，返回文件路径列表。

    report_dir 应按 target 划分（如 reports/src/<target>/）；写入前清理目录中
    旧批次的 *.md，保证「一个漏洞一份文档、目录内只有当前批次」，避免重复
    生成导致一个漏洞堆积多份历史文件。
    文件名 = 序号 + 漏洞名称（sanitize 后）。
    """
    meta = meta or {}
    rdir = Path(report_dir)
    rdir.mkdir(parents=True, exist_ok=True)
    claims = [c for c in (claims or []) if c]
    if not claims:
        return []
    for old in rdir.glob("*.md"):
        old.unlink()
    written = []
    for i, c in enumerate(claims, 1):
        c = _sanitize_claim(c)
        name = build_name(c.vuln_class, c.location, c.statement, platform)
        safe = re.sub(r'[\\/:*?"<>|\s]+', "_", name)[:60].strip("_.，,；;）)")
        fname = f"{i:02d}_{safe}.md"
        body = build_report(
            c, target=target, platform=platform,
            app_version=meta.get("app_version", ""),
            biz_module=meta.get("biz_module", ""),
            test_env=meta.get("test_env", ""),
            account_note=meta.get("account_note", ""),
        )
        p = rdir / fname
        p.write_text(body, encoding="utf-8")
        written.append(str(p))
    return written
