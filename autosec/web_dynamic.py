"""Web 动态分析工作流 - 请求重放 + 双账号差分对比 + 逻辑漏洞证据升级。

P4 关键补齐：mobile 面有 mobile_dynamic，web 面此前缺失动态验证，导致 idor-api /
auth-bypass / priv-escalation 等逻辑类漏洞（SRC 高赏金主力）无 oracle、永远停在
probable，与完成标准（confirmed 才可收尾）形成死锁。

本模块提供三个能力：
  1. probe_environment()        探测 curl / python-requests / httpx 可用性
  2. build_dynamic_plan()       静态 Finding -> Web 动态验证计划（重放/差分/未授权访问）
  3. 差分对比执行器             replay() + compare_responses() + format_diff_evidence()
     双账号（或 无凭证 vs 有凭证）同请求对比，产出标准化 [DIFF] 证据行，
     供 verify.py 的 idor-api / auth-bypass / priv-escalation oracle 升级 confirmed。

[DIFF] 证据格式（机器可校验，verify.py 按此判定）：
  [DIFF] <METHOD> <url> | <A身份>=<status>(<len>B) | <B身份>=<status>(<len>B) | body_sim=<0-1> | VERDICT: <MARKER>
MARKER ∈ IDOR_CONFIRMED | AUTHZ_BYPASS | PRIV_ESC | NO_DIFF（无差异，非漏洞）
"""
from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

# ── 差分判定阈值 ───────────────────────────────────────────────────────────────
SIM_IDOR_THRESHOLD = 0.90     # 攻击者响应与属主响应相似度 ≥ 此值 => 数据同源（IDOR 成立）
SIM_PRIV_THRESHOLD = 0.85     # 低权响应与管理员响应相似度阈值

# 逻辑漏洞差分 VERDICT 标记（verify.py oracle 依赖这些字符串）
V_IDOR = "IDOR_CONFIRMED"
V_AUTHZ = "AUTHZ_BYPASS"
V_PRIV = "PRIV_ESC"
V_NONE = "NO_DIFF"

# 可做差分验证的逻辑漏洞类别（静态 probable -> 动态 confirmed 的升级路径）
_DIFF_CLASSES = {
    "idor-api", "idor", "auth-bypass", "priv-escalation", "privilege-escalation",
    "info-leak", "sms-otp-bypass",
}


# ── 环境探测 ───────────────────────────────────────────────────────────────────
@dataclass
class WebDynEnv:
    curl: bool = False
    requests: bool = False
    httpx: bool = False
    detail: str = ""

    @property
    def ready(self) -> bool:
        return self.curl or self.requests or self.httpx

    def capability_note(self) -> str:
        if self.ready:
            return f"Web 动态就绪 curl={self.curl} requests={self.requests} httpx={self.httpx}"
        return "无 HTTP 重放工具 -> 仅输出验证计划与手工步骤"


def probe_environment(python: str = "python") -> WebDynEnv:
    env = WebDynEnv()
    env.curl = shutil.which("curl") is not None
    try:
        r = subprocess.run([python, "-c", "import requests"], capture_output=True,
                           timeout=15, check=False)
        env.requests = r.returncode == 0
    except Exception:  # noqa: BLE001
        env.requests = False
    try:
        r = subprocess.run([python, "-c", "import httpx"], capture_output=True,
                           timeout=15, check=False)
        env.httpx = r.returncode == 0
    except Exception:  # noqa: BLE001
        env.httpx = False
    env.detail = env.capability_note()
    return env


# ── 请求重放 ───────────────────────────────────────────────────────────────────
@dataclass
class ReplayResult:
    """一次请求重放的结果摘要。"""
    label: str = ""          # 身份标签（owner/attacker/admin/guest/anonymous...）
    status: int = 0
    body_len: int = 0
    body_snippet: str = ""   # 响应体片段（去敏后保留用于相似度）
    error: str = ""


def replay(url: str, *, method: str = "GET", headers: Optional[dict] = None,
           body: str = "", label: str = "", python: str = "python",
           timeout: int = 20, use_curl: bool = False) -> ReplayResult:
    """用 requests（首选）或 curl 重放一次请求，返回结构化摘要。

    任何失败都降级为带 error 的 ReplayResult，绝不抛异常。
    """
    headers = headers or {}
    if not use_curl:
        script = (
            "import sys,json\n"
            "try:\n"
            "    import requests\n"
            f"    r = requests.request({method!r}, {url!r}, headers={json.dumps(headers)!r},"
            f"    data={body!r} or None, timeout={timeout})\n"
            "    print(r.status_code)\n"
            "    print(len(r.content))\n"
            "    print(r.text[:4000])\n"
            "except Exception as e:\n"
            "    print('ERR:'+str(e)[:300])\n"
        )
        try:
            r = subprocess.run([python, "-c", script], capture_output=True,
                               text=True, timeout=timeout + 15, check=False)
            out = (r.stdout or "").strip()
            if out.startswith("ERR:"):
                return ReplayResult(label=label, error=out[4:])
            lines = out.split("\n", 2)
            return ReplayResult(label=label, status=int(lines[0]),
                                body_len=int(lines[1]),
                                body_snippet=(lines[2] if len(lines) > 2 else "")[:4000])
        except Exception as e:  # noqa: BLE001
            if shutil.which("curl"):
                pass  # 落到 curl 兜底
            else:
                return ReplayResult(label=label, error=f"requests 重放失败: {e}")
    # curl 兜底
    if shutil.which("curl"):
        argv = ["curl", "-s", "-o", "-", "-w", "\\n__STATUS__%{http_code}",
                "-X", method, "--max-time", str(timeout)]
        for k, v in headers.items():
            argv += ["-H", f"{k}: {v}"]
        if body:
            argv += ["-d", body]
        argv.append(url)
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=timeout + 15, check=False)
            out = r.stdout or ""
            m = re.search(r"__STATUS__(\d{3})\s*$", out)
            status = int(m.group(1)) if m else 0
            raw = re.sub(r"\n?__STATUS__\d{3}\s*$", "", out)
            return ReplayResult(label=label, status=status, body_len=len(raw),
                                body_snippet=raw[:4000])
        except Exception as e:  # noqa: BLE001
            return ReplayResult(label=label, error=f"curl 重放失败: {e}")
    return ReplayResult(label=label, error="无 requests 也无 curl，无法重放")


def body_similarity(a: ReplayResult, b: ReplayResult) -> float:
    """两个响应体的相似度（0-1）。动态页面去数字/时间戳后比较更稳。"""
    if not a.body_snippet and not b.body_snippet:
        return 1.0 if (a.status == b.status) else 0.0
    if not a.body_snippet or not b.body_snippet:
        return 0.0
    # 去掉易变的数字/时间戳/id 片段，降低误判
    scrub = lambda s: re.sub(r"\d{2,}|[0-9a-f]{8,}", "#", s)
    return difflib.SequenceMatcher(None, scrub(a.body_snippet), scrub(b.body_snippet)).ratio()


# ── 差分对比与标准化证据 ───────────────────────────────────────────────────────
def compare_responses(privileged: ReplayResult, unprivileged: ReplayResult,
                      *, mode: str = "idor") -> tuple[str, float, str]:
    """对比「属主/高权」与「攻击者/低权」的响应，返回 (VERDICT标记, 相似度, 依据说明)。

    mode:
      idor  - 攻击者用自己会话访问属主资源：200 + 高相似 => IDOR_CONFIRMED
      authz - 匿名/低权访问受保护资源：200 + 有内容 => AUTHZ_BYPASS
      priv  - 低权角色访问管理接口：200 + 内容与管理员高相似 => PRIV_ESC
    """
    sim = body_similarity(privileged, unprivileged)
    if mode == "authz":
        if unprivileged.status == 200 and unprivileged.body_len > 0:
            return V_AUTHZ, sim, f"无凭证请求 {unprivileged.status} 且返回 {unprivileged.body_len}B 内容"
        return V_NONE, sim, f"无凭证请求被拒（status={unprivileged.status}）"
    if mode == "priv":
        if (unprivileged.status == 200 and privileged.status == 200
                and sim >= SIM_PRIV_THRESHOLD and unprivileged.body_len > 0):
            return V_PRIV, sim, f"低权角色与管理员响应相似度 {sim:.2f}"
        return V_NONE, sim, f"低权请求未获得管理内容（status={unprivileged.status}, sim={sim:.2f}）"
    # idor 默认
    if (unprivileged.status == 200 and privileged.status == 200
            and sim >= SIM_IDOR_THRESHOLD and unprivileged.body_len > 0):
        return V_IDOR, sim, f"攻击者会话获得与属主同源数据（相似度 {sim:.2f}）"
    if unprivileged.status == 200 and privileged.status in (401, 403):
        # 属主反而被拒（少见，可能是鉴权误配），降级说明
        return V_NONE, sim, f"属主请求被拒（{privileged.status}），上下文异常需人工复核"
    return V_NONE, sim, f"攻击者未获得属主数据（status={unprivileged.status}, sim={sim:.2f}）"


def format_diff_evidence(method: str, url: str, privileged: ReplayResult,
                         unprivileged: ReplayResult, verdict: str, sim: float,
                         rationale: str = "") -> str:
    """把差分结果格式化为标准化 [DIFF] 证据行（verify.py oracle 的匹配对象）。"""
    return (f"[DIFF] {method.upper()} {url} | "
            f"{privileged.label or 'A'}={privileged.status}({privileged.body_len}B) | "
            f"{unprivileged.label or 'B'}={unprivileged.status}({unprivileged.body_len}B) | "
            f"body_sim={sim:.2f} | VERDICT: {verdict}"
            + (f" | {rationale}" if rationale else ""))


def run_differential(url: str, *, method: str = "GET",
                     headers_priv: Optional[dict] = None,
                     headers_unpriv: Optional[dict] = None,
                     body: str = "", label_priv: str = "owner",
                     label_unpriv: str = "attacker", mode: str = "idor",
                     python: str = "python") -> tuple[str, list[ReplayResult]]:
    """一条命令完成双身份重放 + 差分判定 + 标准化证据输出。

    返回 (标准[DIFF]证据行, [属主结果, 攻击者结果])。异常全部降级，证据行带 ERR。
    """
    rp = replay(url, method=method, headers=headers_priv, body=body,
                label=label_priv, python=python)
    ru = replay(url, method=method, headers=headers_unpriv, body=body,
                label=label_unpriv, python=python)
    if rp.error or ru.error:
        err = rp.error or ru.error
        return f"[DIFF] {method.upper()} {url} | ERR: {err}", [rp, ru]
    verdict, sim, why = compare_responses(rp, ru, mode=mode)
    return format_diff_evidence(method, url, rp, ru, verdict, sim, why), [rp, ru]


# ── 动态验证计划 ───────────────────────────────────────────────────────────────
@dataclass
class WebPlanItem:
    """一条 Web 动态验证计划。"""
    target: str
    rationale: str
    command: str               # 可直接执行的命令
    evidence_expected: str     # 期望证据（oracle 匹配串）
    mode: str = ""             # idor / authz / priv / replay
    headers_priv: dict = field(default_factory=dict)
    headers_unpriv: dict = field(default_factory=dict)


def build_dynamic_plan(static_findings: list, target: str = "") -> list[WebPlanItem]:
    """把静态/会话 Finding 转成 Web 动态验证计划（差分类优先）。"""
    plan: list[WebPlanItem] = []
    seen: set[tuple] = set()
    base = (target or "https://target.example.com").rstrip("/")
    for f in static_findings or []:
        cls = (getattr(f, "vuln_class", "") or "").lower()
        loc = (getattr(f, "location", "") or "").strip()
        if not loc:
            continue
        # 位置归一：剥方法前缀（GET/POST ...）；查询串不影响差分目标
        m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(.+)$", loc, re.I)
        if m:
            method, loc = m.group(1).upper(), m.group(2).strip()
        else:
            method = "POST" if "POST" in loc else "GET"
        loc_clean = re.sub(r"[?#].*$", "", loc)
        # 位置归一成绝对 URL（相对路径 -> base + path）
        url = loc_clean if loc_clean.startswith("http") else (
            base + loc_clean if loc_clean.startswith("/") else f"{base}/{loc_clean}")
        if cls in _DIFF_CLASSES:
            key = (url, "diff")
            if key in seen:
                continue
            seen.add(key)
            plan.append(WebPlanItem(
                target=f"{cls}@{loc}", rationale="逻辑漏洞需双账号差分实锤（probable->confirmed）",
                command=(f"run_differential({url!r}, method={method!r}, mode='idor', "
                         f"headers_priv={{'Cookie':'<属主会话>'}}, headers_unpriv={{'Cookie':'<攻击者会话>'}})"),
                evidence_expected="VERDICT: IDOR_CONFIRMED", mode="idor"))
        elif cls in ("sqli", "ssti", "cmdi", "xss", "ssrf", "lfi", "pathtrav", "xxe"):
            key = (url, "replay")
            if key in seen:
                continue
            seen.add(key)
            plan.append(WebPlanItem(
                target=f"{cls}@{loc}", rationale="重放触发并固化回显证据",
                command=f"replay({url!r}, method={method!r}) -> 命中回显 oracle",
                evidence_expected=cls, mode="replay"))
    return plan


def render_plan(plan: list, env: WebDynEnv) -> str:
    """渲染成给 agent 的可执行文本。"""
    if not plan:
        return "（无可动态验证的 Web 发现）"
    lines = [f"◆ Web 动态环境: {env.detail}", ""]
    for i, it in enumerate(plan, 1):
        lines.append(f"[步骤 {i}] 验证 {it.target}（mode={it.mode}）")
        lines.append(f"  理由: {it.rationale}")
        lines.append(f"  命令: {it.command}")
        lines.append(f"  期望证据(照抄到 finding.evidence): {it.evidence_expected}")
        lines.append("")
    lines.append("差分用法: from autosec.web_dynamic import run_differential")
    lines.append("  evidence, results = run_differential(url, headers_priv=属主凭证, "
                 "headers_unpriv=攻击者凭证, mode='idor|authz|priv')")
    lines.append("  evidence 即标准 [DIFF] 行，verdict 为 *_CONFIRMED/*_BYPASS/*_ESC 时对应 "
                 "finding 可升级 confirmed")
    return "\n".join(lines)
