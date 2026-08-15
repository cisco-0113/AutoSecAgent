"""否定门（P6 质量安全）— 对抗式防误报，接 LLM 独立反驳视角。

P1 阶段 negation 是占位（无 LLM 安全降级）。P6 补齐：用一个「专司反驳」的独立
视角审视每个 finding，排除环境噪声 / 诱饵 / 非唯一解释，降低误报进报告的概率。

设计原则（对齐 verify.py「绝不虚报 confirmed」）：
  * 否定门「未真正执行（无 LLM / 调用失败）」时返回 ran=False，verify 不否决，
    安全降级为原判定——绝不因否定门自身故障而误杀真实漏洞。
  * 只有 LLM 真正复核并给出 suspected（大概率误报）时才触发降级。
  * 凭证/证据脱敏后送入 prompt，不落日志。
"""
from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Optional

_NEGATION_RX = re.compile(r"<Negation[^>]*>(.*?)</Negation>", re.IGNORECASE | re.DOTALL)

# 否定门判词
N_CONFIRMED = "confirmed"   # 复核后确认真实漏洞
N_PROBABLE = "probable"     # 有迹象但存疑
N_SUSPECTED = "suspected"   # 大概率误报/噪声/诱饵


@dataclass
class NegationResult:
    """否定门复核结果。"""
    verdict: str = ""            # confirmed/probable/suspected（空=未跑）
    reasons: list = field(default_factory=list)
    ran: bool = False            # 是否真正执行了 LLM 复核

    @property
    def should_downgrade(self) -> bool:
        """是否触发降级（只有真正复核且判 suspected 才降）。"""
        return self.ran and self.verdict == N_SUSPECTED

    @property
    def to_probable(self) -> bool:
        """是否降为 probable（复核判 probable）。"""
        return self.ran and self.verdict == N_PROBABLE


def _build_prompt(claim) -> str:
    """构造否定门 prompt：让 LLM 专司反驳，找出误报的可能。"""
    return f"""你是独立的安全审计复核员，职责是「反驳」下面这个漏洞声明，找出它是误报、环境噪声、诱饵、或存在更无害解释的可能。请以怀疑立场逐条审视：

- 漏洞类别: {claim.vuln_class or '?'}
- 描述: {(claim.statement or '')[:400]}
- 位置: {claim.location or '?'}
- POC: {(claim.poc or '')[:600]}
- 证据: {(claim.evidence or '')[:800]}

审视要点：
1. 证据是否真的支持该漏洞类别？还是模型臆测 / 张冠李戴？
2. 是否存在更无害的解释（正常业务逻辑、测试环境、蜜罐诱饵、误报）？
3. POC 是否可复现、是否越出授权范围？

严格输出一行 JSON（不要额外解释）：
<Negation>{{"verdict":"confirmed|probable|suspected","reasons":["理由1","理由2"]}}</Negation>

verdict 语义：
- confirmed：复核后确认为真实漏洞（证据扎实，无更无害解释）
- probable：有漏洞迹象但存疑（证据非唯一解释、复现不稳定）
- suspected：大概率误报/噪声/诱饵，不应入报告"""


class NegationGate:
    """否定式复核门（接 LLM）。"""

    def __init__(self, engine_fn: Optional[Callable] = None,
                 env: Optional[dict] = None,
                 claude_bin: Optional[str] = None,
                 max_turns: int = 12, session_seconds: int = 180):
        # 延迟 import，避免无 claude 环境时加载失败
        self._engine_fn = engine_fn
        self.env = env or {}
        self.claude_bin = claude_bin
        self.max_turns = max_turns
        self.session_seconds = session_seconds

    def _engine(self):
        if self._engine_fn is not None:
            return self._engine_fn
        from .engine import run_session
        return run_session

    def challenge(self, claim, workdir: Optional[str] = None) -> NegationResult:
        """对单个 claim 执行否定复核。任何失败都返回 ran=False（不否决）。"""
        prompt = _build_prompt(claim)
        wd = workdir or tempfile.mkdtemp(prefix="negation_")
        try:
            er = self._engine()(
                prompt, wd,
                claude_bin=self.claude_bin, env=self.env,
                max_turns=self.max_turns, session_seconds=self.session_seconds,
            )
        except Exception:  # noqa: BLE001
            return NegationResult(ran=False)

        text = er.final_text or ""
        m = _NEGATION_RX.search(text)
        if not m:
            return NegationResult(ran=False)
        try:
            data = json.loads(m.group(1).strip())
            verdict = str(data.get("verdict", "")).lower()
            reasons = [str(r) for r in data.get("reasons", [])][:6]
        except (json.JSONDecodeError, AttributeError):
            return NegationResult(ran=False)
        if verdict not in (N_CONFIRMED, N_PROBABLE, N_SUSPECTED):
            return NegationResult(ran=False)
        return NegationResult(verdict=verdict, reasons=reasons, ran=True)
