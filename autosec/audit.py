"""审计日志（JSONL）。

借鉴 CyberStrikeAI 的强制审计理念：记录每次工具调用、命令、结果摘要与时间戳。
P0 阶段实现基于标准库的轻量日志，支持控制台 + 文件双写。
"""
from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_AUDIT_SESSION_ID = uuid.uuid4().hex[:8]


class AuditLogger:
    """JSONL 审计日志器。线程安全（logging 内部加锁）。"""

    def __init__(self, log_dir: str | Path, name: str = "autosec"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = _AUDIT_SESSION_ID

        stamp = time.strftime("%Y%m%d-%H%M%S")
        file_path = self.log_dir / f"audit-{stamp}-{self.session_id}.jsonl"

        self._logger = logging.getLogger(f"{name}.audit.{self.session_id}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()
        self._logger.propagate = False

        fh = logging.FileHandler(file_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        self._logger.addHandler(fh)

    def _emit(self, event: str, **kv: Any) -> None:
        rec = {
            "ts": time.time(),
            "event": event,
            "session": self.session_id,
            **kv,
        }
        self._logger.debug(json.dumps(rec, ensure_ascii=False, default=str))

    def tool_call(self, tool: str, args: dict | None = None, **kv: Any) -> None:
        self._emit("tool_call", tool=tool, args=args if args is not None else {}, **kv)

    def target(self, target: str, classification: dict | None = None, **kv: Any) -> None:
        self._emit("target", target=target, classification=classification or {}, **kv)

    def finding(self, level: str, title: str, **kv: Any) -> None:
        self._emit("finding", level=level, title=title, **kv)

    def error(self, msg: str, **kv: Any) -> None:
        self._logger.error(json.dumps(
            {"ts": time.time(), "event": "error", "session": self.session_id, "msg": msg, **kv},
            ensure_ascii=False, default=str))

    def close(self) -> None:
        for h in self._logger.handlers:
            h.close()
            self._logger.removeHandler(h)


def console_logger(name: str = "autosec") -> logging.Logger:
    """终端日志器（彩色/级别过滤由 logging 配置）。"""
    lg = logging.getLogger(f"console.{name}")
    if lg.handlers:
        return lg
    lg.setLevel(logging.INFO)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    lg.addHandler(h)
    return lg