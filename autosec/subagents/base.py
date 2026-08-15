"""子代理基类。

每个子代理由 系统提示词 + 工具集配方 + 专属知识卡 三部分组成。
P1 阶段接入执行引擎：execute() 构造 prompt → 调 engine.run_session → 对 findings
过三重校验门 → 返回结构化漏洞清单。

P1.5 收尾逻辑强化（面向 SRC 目标）：引擎单次会话返回后做「达标判定」——
CTF 模式必须实际捕获 flag、实战模式必须产出至少一个带可复现 POC 的 confirmed
漏洞；未达标且预算未耗尽时，携带 Handoff/已确认发现/差距分析自动续接会话，
直到达标或预算（轮数/挂钟/续接轮次）耗尽。杜绝「证据已充分」式提前收尾。
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..audit import console_logger
from ..engine import Finding
from ..verify import VulnClaim, VulnVerifier, make_claim
from ..knowledge import CTFKnowledge, SelfLearningStore, learn_from_result

log = console_logger("subagent")

# CTF flag 常见形态（大小写不敏感）：HTB{...} / flag{...} / CTF{...} / DASCTF{...} 等
_FLAG_RX = re.compile(r"(?:HTB|flag|CTF|DASCTF|NSSCTF|SUCTF|moectf|ACTF|GWHT|catflag)\{[^}\n]{4,200}\}", re.I)


def detect_flag(text: str) -> str:
    """从文本中检测 CTF flag，返回首个匹配或空串。"""
    m = _FLAG_RX.search(text or "")
    return m.group(0) if m else ""


@dataclass
class Delegation:
    """主代理交给子代理的交接包。"""
    target: str
    surfaces: list[str]
    route: str = ""
    scope: str = ""                 # 授权范围描述
    target_type: str = ""           # 目标类型（url/ip/apk/ipa/firmware/包名），子代理可按类型调整话术
    max_turns: int = 60
    session_seconds: int = 900
    max_continue_rounds: int = 2    # 未达标时的续接会话上限（总会话数 = 1 + 该值）
    dry_run: bool = False           # 无 claude 环境时用示例 finding 演示闭环
    engine_env: dict | None = None  # 注入子会话的环境变量（Anthropic 兼容端点）
    ctf_mode: bool = False          # CTF/靶场模式：注入场景边界 + CTF 知识
    ctf_skill_dir: str = ""         # 本地 ctf-skills 目录
    knowledge_dir: str = ""         # 自学习知识库目录


@dataclass
class SubagentResult:
    """子代理执行结果。"""
    surface: str = ""
    findings: list = field(default_factory=list)      # 原始 Finding
    tool_outputs: list = field(default_factory=list)  # [(tool, args, output)] 引擎原始工具调用
    claims: list[VulnClaim] = field(default_factory=list)  # 校验后的 Claim
    confirmed: list[VulnClaim] = field(default_factory=list)  # confirmed 漏洞
    handoff: str = ""
    evidence: str = ""                # 合并的 grounding 证据（跨续接轮次累积）
    num_turns: int = 0
    error: str = ""
    _verified_count: int = 0          # 已校验 findings 数（增量校验游标，内部用）


class Subagent:
    """攻击面子代理基类。"""

    name: str = ""
    display_name: str = ""
    tool_dir: str = ""
    knowledge_entries: list[str] = field(default_factory=list)
    system_prompt: str = ""

    def __init__(self, tool_base_dir: str | Path = "tools",
                 verify_require_poc: bool = True,
                 negator=None):
        self.tool_base_dir = Path(tool_base_dir)
        self.verifier = VulnVerifier(require_poc=verify_require_poc, negator=negator)

    # -- 子类需实现：构造给执行引擎的提示词 + 配置引擎参数 ----
    def build_prompt(self, d: Delegation) -> str:
        raise NotImplementedError

    def engine_env(self) -> dict | None:
        return None

    # -- 子类可覆写：dry-run 时提供的示例 finding（用于无 claude 环境演示） ----
    def dry_run_findings(self, d: Delegation) -> list:
        return []

    # -- 知识注入：CTF 知识包 + 自学习回灌（在 build_prompt 末尾追加） ----
    def knowledge_context(self, d: Delegation) -> str:
        """构造注入子会话的知识上下文（安全红线 + CTF 场景边界 + 自学习经验）。

        安全红线为最高优先级，无论 CTF/实战模式都注入，杜绝破坏性测试。
        """
        from ..safety import SAFETY_REDLINES
        parts: list[str] = [SAFETY_REDLINES]
        learned = SelfLearningStore(d.knowledge_dir or None)
        if d.ctf_mode and d.ctf_skill_dir:
            ctf = CTFKnowledge(d.ctf_skill_dir)
            if ctf.is_available():
                parts.append(ctf.build_pack(self.name))
            else:
                log.warning("[%s] CTF skill 目录不可用: %s", self.name, d.ctf_skill_dir)
        parts.append(learned.render(category=self.name))
        return "\n\n".join(p for p in parts if p)

    # -- 自学习：闭环后把本次经验写入知识库 ----
    def apply_learning(self, d: Delegation, res: SubagentResult, evidence: str = "") -> None:
        try:
            if d.dry_run:
                return
            store = SelfLearningStore(d.knowledge_dir or None)
            entries = learn_from_result(
                self.name, d.target, res.findings, res.handoff,
                evidence, res.tool_outputs)
            n = store.record_many(entries)
            if n:
                log.info("[%s] 自学习记录 %d 条经验 → %s", self.name, n, store.file)
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] 自学习记录失败: %s", self.name, e)

    # -- 会话信息实时输出：供运行状态确认与调试 ----
    def _session_logger(self, kind: str, text: str) -> None:
        """引擎流式回调：把子代理会话的每个动作实时打印。"""
        if kind == "assistant":
            line = text.replace("\n", " ").strip()
            if line:
                log.info("[%s-session] assistant: %s", self.name, line[:300])
        elif kind == "tool_use":
            log.info("[%s-session] ── 调用工具: %s", self.name, text)
        elif kind == "tool_result":
            log.info("[%s-session]    工具结果: %s", self.name, text)
        elif kind == "console":
            t = text.strip()
            if t and not t.startswith("Warning"):
                log.info("[%s-session] >>> %s", self.name, t[:200])
        elif kind == "error":
            log.warning("[%s-session] ✗ %s", self.name, text)

    # -- 公共执行闭环 ----
    def execute(self, d: Delegation, engine=None) -> SubagentResult:
        res = SubagentResult(surface=self.name)
        prompt = self.build_prompt(d)
        log.info("[%s] 构造提示词 (%d 字符)", self.name, len(prompt))

        if d.dry_run:
            findings = self.dry_run_findings(d)
            for f in findings:
                res.findings.append(f)
            log.info("[%s] dry-run 找到 %d 个示例 finding", self.name, len(findings))
            # dry-run 下把各 finding 自带 evidence 合并后走统一增量校验
            res.evidence = "\n".join(f.evidence for f in findings if f.evidence)
            self._verify_new_findings(d, res)
            return res
        else:
            if engine is None:
                from ..engine import run_session
                engine = run_session
            try:
                self._run_until_goal(d, res, engine, prompt)
            except Exception as e:  # noqa: BLE001
                res.error = f"引擎执行异常: {e}"
                log.warning("[%s] %s", self.name, res.error)
                return res
            if not res.findings:
                res.error = "引擎未产出 finding"
                self.apply_learning(d, res, res.evidence)
                return res

        self.apply_learning(d, res, res.evidence)
        return res

    def _verify_new_findings(self, d: Delegation, res: SubagentResult) -> None:
        """对尚未校验的 findings 增量走三重校验门（续接循环每轮调用）。"""
        for f in res.findings[res._verified_count:]:
            poc = f.raw or f.description
            # flag 类 finding：以 flag 原文为 expect sentinel，直接 strong 校验
            expect = f.evidence if f.vuln_class.lower() == "flag" else ""
            # 证据优先取 finding 自身 evidence（避免多条漏洞证据互相串扰），
            # 仅当 finding 无 evidence 时才用合并证据兜底
            evidence = f.evidence or res.evidence
            claim = make_claim(f, evidence, poc=poc, expect=expect)
            self.verifier.verify(claim)
            res.claims.append(claim)
            if claim.verdict == "confirmed":
                res.confirmed.append(claim)
            log.info("[%s] %s confidence=%.1f verdict=%s %s",
                     self.name, claim.vuln_class or "?", claim.confidence,
                     claim.verdict, claim.location)
        res._verified_count = len(res.findings)

    # ── P1.5 达标驱动续接循环 ────────────────────────────────────────────────
    def _goal_met(self, d: Delegation, res: SubagentResult) -> tuple[bool, str]:
        """达标判定：CTF 模式必须捕获 flag；实战模式必须有 confirmed 漏洞。

        返回 (是否达标, 差距描述)。未达标时的差距描述用于续接 prompt。
        """
        blob = "\n".join([
            res.evidence, res.handoff,
            " ".join(f.description + " " + f.evidence + " " + f.raw for f in res.findings),
        ])
        if d.ctf_mode:
            flag = detect_flag(blob)
            if flag:
                return True, ""
            return False, "尚未实际捕获 flag（仅确认漏洞存在不算完成，必须走完利用链读取到 flag 原文）"
        # 实战/SRC 模式：至少一个 finding 通过校验门成为 confirmed（含可复现 POC）
        if res.confirmed:
            return True, ""
        if res.findings:
            return False, ("已有 suspected/probable 发现，但尚无带可复现 POC 的 confirmed 漏洞；"
                           "请继续推进利用链，用真实请求/响应把至少一个发现升级为 confirmed")
        return False, "尚无有效发现，请换攻击面/换漏洞类别继续挖掘"

    def _continuation_prompt(self, d: Delegation, res: SubagentResult,
                             gap: str, round_no: int) -> str:
        """构造续接会话 prompt：携带遗留状态 + 已确认进展 + 差距，禁止重复侦察。"""
        found = "\n".join(
            f"  - [{f.vuln_class or '?'}] {f.location or '?'}: {(f.description or '')[:120]}"
            for f in res.findings[-10:]
        ) or "  （暂无）"
        return f"""【续接会话 · 第 {round_no} 轮】你上一轮的漏洞挖掘尚未达标，禁止就此收尾。

目标: {d.target}（授权范围不变）

差距（必须解决）: {gap}

你已确认的进展（不要重复验证，直接在此基础上推进）:
{found}

你上一轮留下的 Handoff:
{res.handoff or '（未填写，这次必须写清下一步计划）'}

要求:
1. 不要重复已完成的侦察与探测，直接从利用链的断点继续。
2. 每条新命令都必须推进最终目标（{"拿到 flag 原文" if d.ctf_mode else "产出可复现 POC 的 confirmed 漏洞"}）。
3. 若某条路径连续失败 2 次，立即切换备选路径，不要在死胡同上空耗。
4. 达标后用 <Finding> 输出结构化结果（CTF 模式 finding 中必须含 flag 原文），并填 <Handoff>。"""

    def _run_until_goal(self, d: Delegation, res: SubagentResult,
                        engine, prompt: str) -> None:
        """引擎续接循环：跑会话 → 达标判定 → 未达标且预算够则带 Handoff 续接。

        预算语义：d.max_turns / d.session_seconds 为子代理级总预算，跨会话累计消耗。
        """
        t0 = time.time()
        turns_used = 0
        seen_findings: set[str] = set()
        workdir = str(self.tool_base_dir.parent / "data" / "work" / self.name)
        max_rounds = 1 + max(0, d.max_continue_rounds)

        for round_no in range(1, max_rounds + 1):
            remaining_turns = max(10, d.max_turns - turns_used)
            remaining_secs = d.session_seconds - int(time.time() - t0)
            if remaining_secs < 120:
                log.info("[%s] 挂钟预算耗尽（已用 %ds），停止续接", self.name, int(time.time() - t0))
                break

            er = engine(
                prompt, workdir,
                max_turns=remaining_turns, session_seconds=remaining_secs,
                env=d.engine_env or self.engine_env(),
                on_session=self._session_logger,
                transcript_path=str(self.tool_base_dir.parent / "data" / "work" / self.name
                                    / f"transcript-round{round_no}.log"),
            )
            turns_used += er.num_turns
            res.num_turns = turns_used
            log.info("[%s] 第 %d 轮: %d findings / %d turns (err=%s)",
                     self.name, round_no, len(er.findings), er.num_turns, er.error or "-")

            # 合并产出（findings 按 class+location 去重）
            new_findings = 0
            for f in er.findings:
                key = f"{f.vuln_class}|{f.location}"
                if key not in seen_findings:
                    seen_findings.add(key)
                    res.findings.append(f)
                    new_findings += 1
            res.tool_outputs.extend(er.tool_outputs)
            if er.evidence:
                res.evidence = (res.evidence + "\n" + er.evidence)[-400_000:]
            if er.handoff:
                res.handoff = er.handoff
            if er.error:
                res.error = er.error

            # CTF 兜底：拿到了 flag 但引擎没输出 Finding，合成一条避免漏报
            flag = detect_flag(res.evidence + "\n" + res.handoff)
            if d.ctf_mode and flag and not res.findings:
                res.findings.append(Finding(
                    vuln_class="flag", confidence="confirmed",
                    description=f"成功捕获 flag: {flag}",
                    location=d.target, evidence=flag,
                ))

            # 增量校验后再做达标判定（实战模式依赖 confirmed 非空）
            self._verify_new_findings(d, res)
            ok, gap = self._goal_met(d, res)
            if ok:
                log.info("[%s] 第 %d 轮达标，收尾（累计 %d turns / %ds）",
                         self.name, round_no, turns_used, int(time.time() - t0))
                return
            if round_no < max_rounds:
                if new_findings == 0 and not er.evidence:
                    log.info("[%s] 第 %d 轮无任何产出，继续续接意义不大，提前收尾", self.name, round_no)
                    return
                log.info("[%s] 第 %d 轮未达标（%s），续接会话继续", self.name, round_no, gap)
                prompt = self._continuation_prompt(d, res, gap, round_no + 1)

        log.info("[%s] 续接轮次耗尽（%d 轮 / %d turns），按当前产出收尾",
                 self.name, max_rounds, turns_used)

    def describe(self) -> str:
        return (f"[{self.name}] {self.display_name} · "
                f"知识卡 {len(self.knowledge_entries)} 张 · 工具目录 {self.tool_dir or '未配置'}")