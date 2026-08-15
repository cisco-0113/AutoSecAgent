"""编排主代理（Orchestrator）。

职责：
  1. 接收目标 → 授权校验 → 攻击面分类
  2. 按分类唤醒对应子代理，构建交接包并委派执行
  3. 收集子代理的 confirmed 漏洞，输出清单
"""
from __future__ import annotations

import re
from pathlib import Path

from .audit import AuditLogger, console_logger
from .authorization import check as auth_check, load_authorization
from .classifier import Classification, classify, display
from .config import Config
from .report import generate_report
from .subagents.base import Delegation, SubagentResult
from .subagents.iot import IoTSubagent
from .subagents.mobile import MobileSubagent
from .subagents.web import WebSubagent

log = console_logger("orchestrator")

# 攻击面 -> 子代理工厂（P1 接入 Web；P2 接入 Mobile；P3 接入 IoT）
_SUBAGENT_FACTORIES = {
    "web": WebSubagent,
    "mobile": MobileSubagent,
    "iot": IoTSubagent,
}


class Orchestrator:
    """AutoSecAgent 编排主代理。"""

    def __init__(self, config: Config):
        self.cfg = config
        self.cfg.resolve_paths()
        self.audit = AuditLogger(self.cfg.data_dir)
        log.info("AutoSecAgent orchestrator 已初始化 (session=%s)", self.audit.session_id)

    def run(self, target: str, auth_file: str | None = None,
            dry_run: bool = False) -> list[SubagentResult]:
        # 1) 授权校验（硬约束）
        auth = auth_file or self.cfg.auth_file
        ok, msg = auth_check(self.cfg.auth_required, auth, target)
        if not ok:
            self.audit.error(f"授权校验未通过: {msg}")
            raise PermissionError(msg)
        log.info("授权: %s", msg)

        # 提取授权范围的 scope/notes，注入子代理，让 agent 了解完整授权边界
        # （含核心业务清单、APK 获取渠道等），避免只看到「已获授权」四字。
        auth_scope = "已获授权"
        try:
            ao = load_authorization(auth)
            auth_scope = "；".join(x for x in [ao.scope, ao.notes] if x) or "已获授权"
        except Exception:  # noqa: BLE001
            pass

        # 2) 攻击面分类
        clf = classify(target)
        self.audit.target(target, classification={
            "type": clf.target_type,
            "surfaces": clf.attack_surfaces,
            "route": clf.route,
            "confidence": clf.confidence,
        })
        log.info("目标分类结果:\n%s", display(clf))

        # 3) 攻击面过滤（config 限定范围）
        surfaces = [s for s in clf.attack_surfaces if s in self.cfg.attacksurfaces]
        if not surfaces:
            log.warning("目标分类结果不在允许的攻击面范围内: %s", self.cfg.attacksurfaces)
            return []

        # 4) 委派子代理执行
        negator = self._build_negator()
        results = []
        for surface in surfaces:
            factory = _SUBAGENT_FACTORIES.get(surface)
            if factory is None:
                log.info("-> [%s] 子代理将在后续里程碑接入 (P2/P3)", surface)
                continue
            sub = factory(self.cfg.tool_dir, verify_require_poc=self.cfg.require_poc,
                          negator=negator)
            log.info("-> 委派子代理 [%s]", surface)
            handoff = Delegation(
                target=target, surfaces=[surface], route=clf.route,
                scope=auth_scope,
                target_type=clf.target_type,
                max_turns=self.cfg.max_turns, session_seconds=self.cfg.session_seconds,
                max_continue_rounds=self.cfg.max_continue_rounds,
                dry_run=dry_run, engine_env=self.cfg.engine_env(),
                ctf_mode=self.cfg.ctf_mode,
                ctf_skill_dir=self.cfg.ctf_skill_dir,
                knowledge_dir=self.cfg.knowledge_dir,
            )
            res = sub.execute(handoff)
            results.append(res)
            for c in res.confirmed:
                self.audit.finding("confirmed", c.statement,
                                   vuln_class=c.vuln_class, location=c.location)

        # 5) P4 报告生成：收敛去重 -> Markdown/JSON 落盘（挖到即可交付）
        if results:
            try:
                meta = {
                    "scope": "已获授权（见授权声明）",
                    "surfaces": ", ".join(surfaces),
                    "num_turns": sum(r.num_turns for r in results),
                    "engine": self.cfg.engine_provider,
                    "tool_outputs": sum(len(r.tool_outputs) for r in results),
                }
                md, js, n_conf, n_pend = generate_report(
                    results, target, self.cfg.report_dir, meta)
                log.info("P4 报告已生成: %s (confirmed=%d 待复核=%d)", md, n_conf, n_pend)

                # SRC 单独报告：每个 confirmed/probable 漏洞一份，符合平台提交规范
                src_claims = []
                for r in results:
                    for c in r.confirmed:
                        if all(c.vuln_class != s.vuln_class for s in src_claims):
                            src_claims.append(c)
                    for c in r.claims:
                        if c.verdict in ("confirmed", "probable") and \
                           all(c.vuln_class != s.vuln_class or c.location != s.location
                               for s in src_claims):
                            src_claims.append(c)
                if src_claims:
                    from .srcreport import generate_src_reports
                    # 按 target 分目录：reports/src/<target>/，重新生成时自动替换旧批次
                    safe_t = re.sub(r"[^\w.-]+", "_", target)[-60:] or "target"
                    src_dir = str(Path(self.cfg.report_dir) / "src" / safe_t)
                    files = generate_src_reports(src_claims, target=target,
                                                 report_dir=src_dir, platform="oppo",
                                                 meta={"app_version": "", "biz_module": ""})
                    log.info("SRC 单独报告已生成 %d 份 -> %s", len(files), src_dir)
            except Exception as e:  # noqa: BLE001
                log.warning("报告生成失败（不影响漏洞结果）: %s", e)

        return results

    def _build_negator(self):
        """构建否定门 callable（P6）。未启用或引擎未就绪时返回 None（安全降级不否决）。"""
        if not self.cfg.negation_enabled:
            return None
        ok, _ = self.cfg.engine_ready()
        if not ok:
            log.info("否定门已启用但引擎未就绪，安全降级为不否决")
            return None
        from .negation import NegationGate
        gate = NegationGate(env=self.cfg.engine_env(), claude_bin=self.cfg.engine_cmd)
        return gate.challenge   # callable(claim) -> NegationResult

    def run_batch(self, targets: list[str], surfaces: list[str] | None = None,
                  auth_file: str | None = None, dry_run: bool = False):
        """P5 批量调度：去重 + 续跑。逐个执行，done 自动跳过，中断后可恢复。"""
        from .scheduler import BatchScheduler
        sched = BatchScheduler(self.cfg.batch_state_file or None)
        sched.add_targets(targets, surfaces)
        log.info("批量调度 %d 个目标（去重后 %d 个），状态文件 %s",
                 len(targets), len(sched.tasks), self.cfg.batch_state_file or "（内存）")

        def _runner(task) -> tuple[bool, str, int]:
            try:
                results = self.run(task.target, auth_file=auth_file, dry_run=dry_run)
                n_conf = sum(len(r.confirmed) for r in results)
                return True, "", n_conf
            except PermissionError as e:
                # 授权拒绝视为「完成（跳过）」，不中断批量
                return True, f"授权拒绝（跳过）: {e}", 0
            except Exception as e:  # noqa: BLE001
                return False, str(e), 0

        stats = sched.run_all(_runner)
        log.info("批量完成: %s", stats)
        return stats, sched

    def close(self) -> None:
        self.audit.close()