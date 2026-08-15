"""工具执行治理 — 工具配方加载 + 超时/spill 防超大输出。

借鉴 CyberStrikeAI 的 tooloutput 治理理念：每个工具配方声明超时、并发与输出上限；
超长输出 spill 落盘、回传截断通知，避免撑爆模型上下文。同时提供命令执行壳，
供本地工具（nmap/curl/jadx 等）在子代理之外被治理地调用。
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ToolRecipe:
    """一份 YAML 工具配方。"""
    name: str = ""
    command: str = ""               # 命令模板，{args} 占位
    description: str = ""
    timeout: int = 120              # 秒
    max_output_chars: int = 20000   # 超限 spill 落盘
    surfaces: list[str] = field(default_factory=list)   # 适用攻击面白名单
    dangerous: bool = False         # 是否需授权目标内执行

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ToolRecipe":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(
            name=str(data.get("name", Path(path).stem)),
            command=str(data.get("command", "")),
            description=str(data.get("description", "")),
            timeout=int(data.get("timeout", 120)),
            max_output_chars=int(data.get("max_output_chars", 20000)),
            surfaces=[str(x) for x in data.get("surfaces", [])],
            dangerous=bool(data.get("dangerous", False)),
        )

    @classmethod
    def from_yaml_all(cls, path: str | Path) -> list["ToolRecipe"]:
        """解析可能含多文档(---)的 YAML 配方文件。"""
        docs = yaml.safe_load_all(Path(path).read_text(encoding="utf-8"))
        out: list[ToolRecipe] = []
        for data in docs:
            if not data:
                continue
            out.append(cls(
                name=str(data.get("name", Path(path).stem)),
                command=str(data.get("command", "")),
                description=str(data.get("description", "")),
                timeout=int(data.get("timeout", 120)),
                max_output_chars=int(data.get("max_output_chars", 20000)),
                surfaces=[str(x) for x in data.get("surfaces", [])],
                dangerous=bool(data.get("dangerous", False)),
            ))
        return out


@dataclass
class ToolResult:
    """一次工具执行结果（含 spill 治理信息）。"""
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False
    spill_path: str = ""            # 超长输出落盘位置
    truncated: bool = False         # 是否截断
    elapsed: float = 0.0


class ToolRunner:
    """治理地执行本地安全工具。"""

    def __init__(self, max_output_chars: int = 20000, spill_dir: str = "data/spill"):
        self.max_output_chars = max_output_chars
        self.spill_dir = Path(spill_dir)
        self.spill_dir.mkdir(parents=True, exist_ok=True)

    def run(self, cmd: list[str], *, timeout: int = 120,
            cwd: str | None = None, env: dict | None = None) -> ToolResult:
        """执行命令并治理输出。超长输出 spill 落盘。"""
        start = time.time()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                cwd=cwd, env=env,
            )
            timed_out = False
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            stdout = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout or b"").decode("utf-8", "replace")
            stderr = (e.stderr or "") if isinstance(e.stderr, str) else (e.stderr or b"").decode("utf-8", "replace")
            rc = -1

        result = ToolResult(ok=(rc == 0), stdout=stdout, stderr=stderr,
                            returncode=rc, timed_out=timed_out,
                            elapsed=time.time() - start)

        # spill 治理：超长输出落盘，回传截断 + 通知
        if len(stdout) > self.max_output_chars:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            spill = self.spill_dir / f"spill-{stamp}-{abs(hash(''.join(cmd))) % 100000}.txt"
            try:
                spill.write_text(stdout, encoding="utf-8")
                result.spill_path = str(spill)
                result.truncated = True
                result.stdout = f"[输出已 spill 至 {spill}，本段截断]\n" + stdout[:self.max_output_chars]
            except Exception:  # noqa: BLE001 - spill 失败不致命，仅截断
                result.truncated = True
                result.stdout = stdout[:self.max_output_chars]
        return result

    def load_recipes(self, tool_dir: str | Path, surface: str | None = None) -> list[ToolRecipe]:
        """加载 tools/<surface>/*.yaml 配方，可按攻击面过滤。"""
        recipes: list[ToolRecipe] = []
        d = Path(tool_dir)
        if not d.is_dir():
            return recipes
        for f in sorted(d.glob("*.yaml")):
            try:
                rs = ToolRecipe.from_yaml_all(f)
            except Exception:  # noqa: BLE001
                try:
                    rs = [ToolRecipe.from_yaml(f)]
                except Exception:  # noqa: BLE001
                    continue
            for r in rs:
                if surface and r.surfaces and surface not in r.surfaces:
                    continue
                recipes.append(r)
        return recipes