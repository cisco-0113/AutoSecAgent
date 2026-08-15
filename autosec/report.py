"""P4 漏洞报告生成 - 挖到即可交付。

解决「挖到也交不出」：orchestrator 跑完后把 SubagentResult 收敛成结构化漏洞报告
（Markdown 人读 + JSON 机读），含严重度分级、去重、复现步骤（POC）、修复建议、
运行元数据。输出到 reports/<时间戳>_<目标>_report.md。

设计要点：
  * 去重：跨子代理（mobile+iot 双面委派常撞车）按 vuln_class + location 归一合并
  * 分级：vuln_class -> severity(critical/high/medium/low) + 参考分值，类目优先，
    confirmed 状态不改变分级（分级看漏洞本质，不看验证进度）
  * probable/suspected 进「待复核」附录，不混入正式漏洞清单，防止误报进交付物
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .subagents.base import SubagentResult

# ── 漏洞类别 -> (严重度, 参考分值) ─────────────────────────────────────────────
# 分级口径：RCE/鉴权绕过/车控伪造 = critical；数据获取/凭证泄露/注入 = high；
# 客户端/配置类 = medium/low。
_SEVERITY = {
    # critical
    "cmdi": ("critical", 9.8), "auth-bypass": ("critical", 9.1),
    "control-msg-forgery": ("critical", 9.0), "rce": ("critical", 9.8),
    "priv-escalation": ("critical", 8.8), "privilege-escalation": ("critical", 8.8),
    # high
    "sqli": ("high", 8.6), "idor-api": ("high", 8.1), "idor": ("high", 8.1),
    "ssti": ("high", 8.4), "ssrf": ("high", 7.5), "xxe": ("high", 7.5),
    "hardcoded-cred": ("high", 7.8), "firmware-secret": ("high", 7.6),
    "backdoor-account": ("high", 8.0), "signature-key-leak": ("high", 7.7),
    "mqtt-anon-access": ("high", 7.4), "sms-otp-bypass": ("high", 7.2),
    "topic-info-leak": ("high", 7.0), "info-leak": ("high", 7.0),
    "ota-unsigned": ("high", 8.2), "weak-crypto": ("high", 7.1),
    "runtime-cred": ("high", 7.6), "crypto-key-extract": ("high", 7.3),
    # medium
    "xss": ("medium", 6.1), "lfi": ("medium", 6.5), "pathtrav": ("medium", 5.8),
    "weak-service": ("medium", 6.8), "exported-component": ("medium", 5.5),
    "mqtt-weak-cred": ("medium", 6.3), "known-cve": ("medium", 6.0),
    "insecure-storage": ("medium", 5.2), "webview-jsi": ("medium", 5.9),
    "ssl-unpinning": ("medium", 5.4), "weak-cert-validation": ("medium", 5.6),
    "default-cred": ("medium", 6.6), "firmware-extract": ("medium", 4.8),
    # low
    "debuggable": ("low", 3.4), "allow-backup": ("low", 3.1),
    "cleartext-traffic": ("low", 3.8), "hardcoded-secret": ("low", 4.2),
    "flag": ("info", 0.0),
}

# ── 漏洞类别 -> 修复建议 ───────────────────────────────────────────────────────
_FIXES = {
    "sqli": "参数化查询/预编译语句，禁止字符串拼接 SQL；对报错信息统一收敛不回显数据库细节。",
    "idor-api": "服务端按会话身份校验资源归属（属主检查），禁止仅凭前端传入 ID 取数；对越权访问记录审计日志。",
    "idor": "同 idor-api：接口层做属主校验，列表/详情/导出全链路覆盖。",
    "auth-bypass": "修复鉴权中间件顺序，受保护路由必须先过身份校验；补齐未授权访问的默认拒绝策略。",
    "priv-escalation": "服务端按角色白名单校验管理接口权限，前端隐藏不等于鉴权；管理面增加二次认证。",
    "privilege-escalation": "同 priv-escalation：角色校验落到服务端，管理接口按白名单授权。",
    "ssti": "模板引擎启用沙箱/自动转义，用户输入只作数据不作模板表达式；升级存在沙箱逃逸的模板库版本。",
    "ssrf": "出网请求做目标地址白名单校验，禁用重定向跟随；内网网段/云元数据地址(169.254.169.254)显式拒绝。",
    "xxe": "XML 解析器禁用外部实体（DTD/external general/parameter entity 全关）。",
    "xss": "输出编码按上下文（HTML/JS/URL/属性）分别转义；富文本走白名单过滤；关键 Cookie 加 HttpOnly。",
    "cmdi": "命令参数白名单枚举，禁止用户输入直接拼入 shell；必须执行时用参数化 API（如 subprocess 列表形式）。",
    "lfi": "文件路径规范化后做前缀白名单校验，禁止 `..` 与绝对路径；下载接口改用资源 ID 映射表。",
    "pathtrav": "同 lfi：规范化 + 白名单根目录约束。",
    "debuggable": "release 构建移除 android:debuggable（gradle release 默认 false，检查 Manifest 覆写）。",
    "allow-backup": "Manifest 设置 android:allowBackup=false，敏感数据不落可备份存储。",
    "exported-component": "非必要导出的组件显式 exported=false；必须导出的加权限保护或签名级校验，处理外部 Intent 时校验来源。",
    "hardcoded-secret": "密钥/盐值移出客户端代码，改由服务端签名；历史密钥视为已泄露全部轮换。",
    "hardcoded-cred": "删除硬编码账户口令，改随机初始密码 + 首次强制修改；受影响账户全部重置。",
    "firmware-secret": "私钥/证书从固件镜像移除，改用设备唯一密钥 + 安全存储（TPM/TrustZone）。",
    "backdoor-account": "移除无口令/隐藏账户，审计固件构建管线防止再次引入。",
    "cleartext-traffic": "usesCleartextTraffic=false，全部流量走 TLS 并校验证书。",
    "weak-cert-validation": "实现标准证书链校验，移除信任所有证书的自定义 TrustManager/主机名校验缺省。",
    "webview-jsi": "评估 addJavascriptInterface 必要性；必须保留时仅暴露最小方法集并对 JS 桥来源做域校验（targetSdk>=17 默认仅暴露 @JavascriptInterface）。",
    "insecure-storage": "敏感数据改 EncryptedSharedPreferences/Keystore，不落外部存储与明文数据库。",
    "mqtt-anon-access": "MQTT broker 关闭匿名接入，启用 per-client 证书或强凭证；ACL 限制订阅主题。",
    "mqtt-weak-cred": "轮换弱凭证为高强度随机值，启用账号锁定与异常连接告警。",
    "topic-info-leak": "broker ACL 按客户端身份限制可订阅主题；车辆隐私数据（VIN/GPS）脱敏或加密传输。",
    "control-msg-forgery": "控制指令通道启用双向认证 + 签名/时间戳/nonce 防重放，服务端校验指令来源合法性。",
    "sms-otp-bypass": "验证码不回显响应、一次性使用、有效期<=5min、按手机号+维度限速锁定。",
    "ota-unsigned": "OTA 包服务端签名 + 端侧验签（非对称），升级任务接口加操作者鉴权与审计。",
    "known-cve": "升级受影响组件到已修复版本，短期可加 WAF 规则缓解。",
    "weak-service": "关闭 telnet/ftp/adbd 等调试服务或加防火墙限制，生产固件移除调试 shell。",
    "weak-crypto": "替换自定义/弱加密为标准库（AES-GCM/ChaCha20），密钥不落代码。",
    "runtime-cred": "令牌短时效 + 刷新机制，客户端不持久化长期凭证。",
    "crypto-key-extract": "密钥移入安全硬件（Keystore/TrustZone），白盒或拆分存储并配合反调试检测。",
    "default-cred": "修改所有默认口令，首次部署强制改密。",
    "firmware-extract": "固件加密或签名校验升级流程，提高静态提取成本（纵深防御项）。",
    "info-leak": "数据导出/查询接口加身份鉴权与属主校验，敏感字段按角色脱敏。",
    "signature-key-leak": "签名密钥移服务端，客户端签名视为已泄露，通知业务方轮换。",
    "flag": "CTF 模式产出，无修复项。",
}
_DEFAULT_FIX = "按该类漏洞的行业标准实践加固，并结合上下文做回归验证。"


def _loc_key(location: str) -> str:
    """位置归一化：去查询串/行号/大小写，用于跨子代理去重。"""
    s = (location or "").strip().lower()
    s = re.sub(r"[?#].*$", "", s)
    s = re.sub(r"[:：]\d+$", "", s)      # 行号
    s = re.sub(r"/+", "/", s)
    return s


@dataclass
class ReportEntry:
    """报告中的一条漏洞（可能合并自多个子代理的重复发现）。"""
    vuln_class: str = ""
    statement: str = ""
    location: str = ""
    severity: str = "medium"
    score: float = 5.0
    verdict: str = "probable"
    confidence: float = 0.0
    poc: str = ""
    evidence: str = ""
    reasons: list = field(default_factory=list)
    surfaces: list = field(default_factory=list)   # 来源攻击面（去重后合并）
    fix: str = _DEFAULT_FIX
    ts: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> tuple:
        return (self.vuln_class.lower(), _loc_key(self.location))


def collect_entries(results: list[SubagentResult]) -> tuple[list[ReportEntry], list[ReportEntry]]:
    """从子代理结果收敛 (confirmed 清单, 待复核清单)，跨面去重。

    去重规则：同 vuln_class + 归一化 location 视为同一漏洞，合并来源攻击面，
    保留证据最完整（evidence 最长）的一条。
    """
    confirmed_map: dict[tuple, ReportEntry] = {}
    review: dict[tuple, ReportEntry] = {}
    for res in results or []:
        surface = res.surface
        for c in (res.confirmed or []):
            sev, score = _SEVERITY.get(c.vuln_class.lower(), ("medium", 5.5))
            e = ReportEntry(
                vuln_class=c.vuln_class, statement=c.statement, location=c.location,
                severity=sev, score=score, verdict="confirmed", confidence=c.confidence,
                poc=c.poc, evidence=c.evidence, reasons=list(c.reasons or []),
                surfaces=[surface], fix=_FIXES.get(c.vuln_class.lower(), _DEFAULT_FIX),
            )
            key = e.dedup_key
            if key in confirmed_map:
                old = confirmed_map[key]
                if surface not in old.surfaces:
                    old.surfaces.append(surface)
                if len(e.evidence) > len(old.evidence):
                    old.evidence, old.poc = e.evidence, e.poc
            else:
                confirmed_map[key] = e
        for c in (res.claims or []):
            if getattr(c, "verdict", "") == "confirmed":
                continue        # 已进 confirmed
            sev, score = _SEVERITY.get(c.vuln_class.lower(), ("medium", 5.5))
            e = ReportEntry(
                vuln_class=c.vuln_class, statement=c.statement, location=c.location,
                severity=sev, score=score, verdict=c.verdict, confidence=c.confidence,
                poc=c.poc, evidence=c.evidence, reasons=list(c.reasons or []),
                surfaces=[surface], fix=_FIXES.get(c.vuln_class.lower(), _DEFAULT_FIX),
            )
            if e.dedup_key in confirmed_map:
                continue        # 与 confirmed 重复的不再进待复核
            review.setdefault(e.dedup_key, e)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confirmed = sorted(confirmed_map.values(), key=lambda x: (order.get(x.severity, 9), -x.score))
    pending = sorted(review.values(), key=lambda x: (order.get(x.severity, 9), -x.score))
    return confirmed, pending


# ── 输出 ───────────────────────────────────────────────────────────────────────
def _md_entry(i: int, e: ReportEntry) -> str:
    sev_badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(e.severity, "⚪")
    lines = [
        f"### {i}. [{e.severity.upper()}] {e.vuln_class} — {e.statement or '(无描述)'}",
        "",
        f"- **严重度**: {sev_badge} {e.severity}（参考分值 {e.score}）",
        f"- **位置**: `{e.location or '未知'}`",
        f"- **验证状态**: {e.verdict}（置信度 {e.confidence:.0%}）",
        f"- **来源攻击面**: {', '.join(e.surfaces) or '-'}",
        "",
        f"**证据**",
        "```",
        (e.evidence or "(无)").strip()[:1500],
        "```",
        "",
        f"**复现步骤 (POC)**",
        "```",
        (e.poc or "(见证据)").strip()[:1500],
        "```",
        "",
        f"**修复建议**: {e.fix}",
    ]
    if e.reasons:
        lines.append(f"**校验依据**: {'; '.join(e.reasons)}")
    return "\n".join(lines)


def render_markdown(target: str, confirmed: list[ReportEntry], pending: list[ReportEntry],
                    meta: dict | None = None) -> str:
    meta = meta or {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    parts = [
        f"# AutoSecAgent 漏洞报告",
        "",
        f"- **目标**: `{target}`",
        f"- **生成时间**: {now}",
        f"- **授权范围**: {meta.get('scope', '见授权声明')}",
        f"- **confirmed 漏洞**: {len(confirmed)} 个  |  待复核: {len(pending)} 个",
        "",
        "---",
        "",
    ]
    if confirmed:
        parts.append("## 一、已确认漏洞（confirmed）\n")
        parts.extend(_md_entry(i, e) + "\n" for i, e in enumerate(confirmed, 1))
    else:
        parts.append("## 一、已确认漏洞（confirmed）\n\n本次运行无通过校验门的 confirmed 漏洞。\n")
    if pending:
        parts.append("## 二、待复核发现（未过校验门，仅供人工跟进）\n")
        for i, e in enumerate(pending, 1):
            parts.append(f"{i}. `[{e.severity}] {e.vuln_class}` @ `{e.location}` — {e.statement} ({e.verdict})")
        parts.append("")
    parts.extend([
        "---",
        "",
        "## 附录：运行元数据",
        "",
        f"- 攻击面: {meta.get('surfaces', '-')}",
        f"- 子代理轮次: {meta.get('num_turns', '-')}",
        f"- 引擎: {meta.get('engine', '-')}",
        f"- 工具产出: {meta.get('tool_outputs', '-')} 条工具调用已存审计日志",
        "",
        "> 本报告由 AutoSecAgent 自动生成，所有 confirmed 漏洞均通过三重校验门（真实工具输出作为 grounding 证据）。",
    ])
    return "\n".join(parts)


def save_report(target: str, confirmed: list[ReportEntry], pending: list[ReportEntry],
                report_dir: str | Path, meta: dict | None = None) -> tuple[str, str]:
    """落盘 Markdown + JSON，返回 (md_path, json_path)。"""
    rdir = Path(report_dir)
    rdir.mkdir(parents=True, exist_ok=True)
    safe_target = re.sub(r"[^\w.-]+", "_", target)[-60:]
    stem = time.strftime("%Y%m%d_%H%M%S") + "_" + safe_target
    md = render_markdown(target, confirmed, pending, meta)
    md_path = rdir / f"{stem}_report.md"
    md_path.write_text(md, encoding="utf-8")
    payload = {
        "target": target, "generated_at": time.time(), "meta": meta or {},
        "confirmed": [asdict(e) for e in confirmed],
        "pending_review": [asdict(e) for e in pending],
    }
    json_path = rdir / f"{stem}_report.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(md_path), str(json_path)


def generate_report(results: list[SubagentResult], target: str, report_dir: str | Path,
                    meta: dict | None = None) -> tuple[str, str, int, int]:
    """编排层入口：收敛 -> 渲染 -> 落盘。返回 (md, json, confirmed数, 待复核数)。"""
    confirmed, pending = collect_entries(results)
    md, js = save_report(target, confirmed, pending, report_dir, meta)
    return md, js, len(confirmed), len(pending)
