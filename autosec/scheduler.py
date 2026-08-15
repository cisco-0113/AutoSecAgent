"""批量目标调度（P5 规模化）— 去重 / 续跑 / 状态持久化。

解决「多个目标挨个跑、中断后从头再来、同一目标重复跑」的规模化痛点：
  * 去重：同一 target 归一化后只保留一个任务，surfaces 合并
  * 续跑：状态持久化到 JSONL，重启后 done 的任务自动跳过，从断点继续
  * 重试：failed 任务在 attempts 上限内可重跑
  * 无侵入：通过 runner 回调注入 Orchestrator，避免循环依赖
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

# 任务状态
T_PENDING = "pending"
T_RUNNING = "running"
T_DONE = "done"
T_FAILED = "failed"
T_SKIPPED = "skipped"


@dataclass
class Task:
    target: str = ""
    surfaces: list[str] = field(default_factory=list)
    status: str = T_PENDING
    attempts: int = 0
    last_error: str = ""
    confirmed: int = 0
    updated_at: float = field(default_factory=time.time)

    @property
    def key(self) -> str:
        return _norm_target(self.target)


def _norm_target(t: str) -> str:
    """目标归一化：小写、去协议、去尾部斜杠，用于去重。"""
    t = (t or "").strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.rstrip("/")


class BatchScheduler:
    """批量任务调度器（去重 + 续跑）。"""

    def __init__(self, state_path: str | Path | None = None,
                 max_attempts: int = 2):
        self.state_path = Path(state_path) if state_path else None
        self.max_attempts = max(1, max_attempts)
        self.tasks: list[Task] = []
        if self.state_path and self.state_path.is_file():
            self._load()

    # ── 添加 / 去重 ──
    def add_targets(self, targets: list[str],
                    surfaces: Optional[list[str]] = None) -> int:
        """批量加入目标，同一 target 归一化后合并 surfaces 并去重。"""
        added = 0
        for t in targets or []:
            key = _norm_target(t)
            existing = next((x for x in self.tasks if x.key == key), None)
            if existing is None:
                self.tasks.append(Task(target=t, surfaces=list(surfaces or [])))
                added += 1
            else:
                # 合并 surfaces
                for s in surfaces or []:
                    if s not in existing.surfaces:
                        existing.surfaces.append(s)
        return added

    # ── 调度 ──
    def next_pending(self) -> Optional[Task]:
        """取下一个待跑任务（pending 优先，failed 在重试上限内）。"""
        for t in self.tasks:
            if t.status == T_PENDING:
                return t
        for t in self.tasks:
            if t.status == T_FAILED and t.attempts < self.max_attempts:
                return t
        return None

    def mark_running(self, task: Task) -> None:
        task.status = T_RUNNING
        task.attempts += 1
        task.updated_at = time.time()

    def mark_done(self, task: Task, confirmed: int = 0) -> None:
        task.status = T_DONE
        task.confirmed = confirmed
        task.last_error = ""
        task.updated_at = time.time()

    def mark_failed(self, task: Task, error: str = "") -> None:
        task.status = T_FAILED
        task.last_error = error[:400]
        task.updated_at = time.time()

    def mark_skipped(self, task: Task, reason: str = "") -> None:
        task.status = T_SKIPPED
        task.last_error = reason[:400]
        task.updated_at = time.time()

    # ── 批量执行（runner 回调注入 Orchestrator）──
    def run_all(self, runner: Callable[[Task], tuple[bool, str, int]],
                persist_each: bool = True) -> dict[str, int]:
        """逐个执行任务，done 自动跳过（续跑），failed 在 attempts 上限内自动重试。
        runner 返回 (ok, error, confirmed)。返回值为「最终状态统计」而非执行次数。
        """
        while True:
            task = self.next_pending()
            if task is None:
                break
            self.mark_running(task)
            if persist_each:
                self.persist()
            try:
                ok, err, confirmed = runner(task)
            except Exception as e:  # noqa: BLE001
                ok, err, confirmed = False, f"runner 异常: {e}", 0
            if ok:
                self.mark_done(task, confirmed)
            else:
                self.mark_failed(task, err)
            if persist_each:
                self.persist()
        return self.summary()

    # ── 状态持久化（续跑）──
    def persist(self, path: str | Path | None = None) -> None:
        p = Path(path) if path else self.state_path
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for t in self.tasks:
            d = {"target": t.target, "surfaces": t.surfaces, "status": t.status,
                 "attempts": t.attempts, "last_error": t.last_error,
                 "confirmed": t.confirmed, "updated_at": t.updated_at}
            lines.append(json.dumps(d, ensure_ascii=False))
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _load(self) -> None:
        try:
            for ln in self.state_path.read_text(encoding="utf-8").splitlines():
                if not ln.strip():
                    continue
                d = json.loads(ln)
                self.tasks.append(Task(
                    target=d.get("target", ""), surfaces=d.get("surfaces", []),
                    status=d.get("status", T_PENDING), attempts=d.get("attempts", 0),
                    last_error=d.get("last_error", ""), confirmed=d.get("confirmed", 0),
                    updated_at=d.get("updated_at", 0.0),
                ))
        except (OSError, json.JSONDecodeError):
            self.tasks = []

    def summary(self) -> dict[str, int]:
        from collections import Counter
        return dict(Counter(t.status for t in self.tasks))
