"""执行引擎 — 漏洞挖掘语义的 Claude Code 桥接。

借鉴 hxbai 的 ccrunner 机制：spawn 一个 headless Claude Code 子会话，以 stream-json
模式消费完整 transcript，把真实的 tool_result 作为漏洞 ground-truth 证据流。

与 CTF 版 ccrunner 的关键差异：
  * 提取对象从 flag 变为漏洞 finding（结构化 Claim：类目/位置/证据/影响）
  * 通过 <Finding>...</Finding> 协议让子代理输出结构化漏洞候选
  * 保留 observed_output 作为三方校验门的 grounding 证据

Murphy 原则：claude CLI 缺失 / 超时 / 非 JSON 行 / 空 transcript 一律降级为干净的
EngineResult，绝不崩溃。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

# 漏洞 finding 提取：子代理用 <Finding>JSON</Finding> 输出结构化漏洞候选
_FINDING_RX = re.compile(r"<Finding[^>]*>(.*?)</Finding>", re.IGNORECASE | re.DOTALL)
_HANDOFF_RX = re.compile(r"<Handoff>(.*?)</Handoff>", re.IGNORECASE | re.DOTALL)

_MAX_TOOL_CHARS = 20000       # 单条 tool_result 保留给证据挖掘的长度上限
_MAX_EVIDENCE = 400_000       # grounding 证据缓冲上限（有界）


@dataclass
class Finding:
    """一个漏洞候选（Claim 的粗提取态，交校验门精化）。"""
    vuln_class: str = ""       # sqli/ssti/cmdi/ssrf/idor/lfi/...
    description: str = ""      # 人类可读描述
    location: str = ""         # endpoint / file:line / 组件
    confidence: str = "suspected"   # suspected | probable | confirmed
    evidence: str = ""         # 支撑证据摘要
    raw: str = ""              # 原始 Finding JSON 文本


@dataclass
class EngineResult:
    """一次子代理会话的执行结果。"""
    final_text: str = ""                       # 子代理最终消息
    findings: list[Finding] = field(default_factory=list)   # 漏洞候选
    evidence: str = ""                         # 真实 tool 输出（grounding 证据）
    tool_outputs: list[tuple] = field(default_factory=list)  # [(tool, args, output)]
    handoff: str = ""                          # 遗留状态（下次继续）
    num_turns: int = 0
    is_error: bool = False
    error: str = ""


def extract_findings(text: str) -> list[Finding]:
    """从 <Finding>...</Finding> 块解析结构化漏洞候选。"""
    out: list[Finding] = []
    for m in _FINDING_RX.finditer(text or ""):
        raw = m.group(1).strip()
        if not raw or raw in ("...", "…"):
            continue
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                f = Finding(
                    vuln_class=str(data.get("class", data.get("vuln_class", ""))),
                    description=str(data.get("description", "")),
                    location=str(data.get("location", "")),
                    confidence=str(data.get("confidence", "suspected")),
                    evidence=str(data.get("evidence", "")),
                    raw=raw[:2000],
                )
                if f.vuln_class or f.description:
                    out.append(f)
        except json.JSONDecodeError:
            # 非 JSON 的宽松 fallback：整块当作描述
            out.append(Finding(description=raw[:500], raw=raw[:2000]))
    return out


def extract_handoff(text: str) -> str:
    m = _HANDOFF_RX.search(text or "")
    return m.group(1).strip() if m else ""


def _resolve_launch(binary: str) -> list[str]:
    """解析 claude 可执行路径。

    - 若 binary 已是完整路径，直接使用
    - 否则用 shutil.which 在 PATH 中找
    - Windows 下若是 .cmd/.bat 包装，经 cmd.exe /c 调用（Popen 无法直接跑批处理）
    """
    import shutil

    if os.path.isabs(binary) and os.path.exists(binary):
        path = binary
    else:
        path = shutil.which(binary) or binary
    if os.name == "nt" and path.lower().endswith((".cmd", ".bat")):
        return ["cmd.exe", "/c", path]
    if not os.path.isabs(path):
        return [binary]
    return [path]


def run_session(
    prompt: str,
    workdir: str,
    *,
    claude_bin: Optional[str] = None,
    env: Optional[dict] = None,
    max_turns: int = 60,
    session_seconds: int = 1500,
    on_evidence: Optional[Callable[[str, dict, str], None]] = None,
    on_session: Optional[Callable[[str, str], None]] = None,
    transcript_path: Optional[str] = None,
) -> EngineResult:
    """Spawn 一个 headless Claude Code 子会话执行 `prompt`。

    流式消费 stream-json，把真实 tool_result 汇入 EngineResult.evidence（grounding 证据），
    并回调：
      * on_evidence(tool, args, output) 供审计/黑板挖掘
      * on_session(kind, text) 实时输出会话信息（kind ∈ assistant/tool_use/tool_result/
        console/error），用于运行状态确认与调试
    """
    os.makedirs(workdir, exist_ok=True)
    binary = claude_bin or os.getenv("CLAUDE_BIN", "claude")
    base_env = dict(os.environ)
    if env:
        base_env.update({k: v for k, v in env.items() if v})

    # Windows 下 claude 是 .CMD 批处理包装，Popen 无法直接执行，需解析完整路径并经 cmd.exe 调用
    argv = _resolve_launch(binary)
    argv += [
        "-p",
        "--output-format", "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--max-turns", str(max_turns),
    ]

    res = EngineResult()
    pending: dict[str, tuple] = {}
    assistant_text_parts: list[str] = []
    assistant_turns = 0
    stderr_buf: list[str] = []
    raw_stdout: list[str] = []

    def _emit(kind: str, text: str) -> None:
        if on_session is not None:
            try:
                on_session(kind, text)
            except Exception:  # noqa: BLE001
                pass

    try:
        proc = subprocess.Popen(
            argv, cwd=workdir, env=base_env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        res.is_error = True
        res.error = f"claude CLI 未找到 ({binary}): {e}"
        return res
    except Exception as e:  # noqa: BLE001
        res.is_error = True
        res.error = f"启动 claude 失败: {e}"
        return res

    # ---- 实时流式消费：stdout 线程解析 stream-json，stderr 线程缓冲 ----
    def _drain_stderr() -> None:
        try:
            for ln in proc.stderr:
                stderr_buf.append(ln)
        except Exception:  # noqa: BLE001
            pass

    stdout_done = threading.Event()

    def _consume_stdout() -> None:
        nonlocal assistant_turns
        ev_len = 0
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                raw_stdout.append(line)
                if line[0] != "{":
                    # 非 JSON 的会话控制/警告行，实时输出便于调试
                    _emit("console", line[:300])
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = ev.get("type")
                if etype == "assistant":
                    assistant_turns += 1
                    msg = ev.get("message", {}) or {}
                    for block in msg.get("content", []) or []:
                        if not isinstance(block, dict):
                            continue
                        if block.get("type") == "text":
                            t = block.get("text", "")
                            assistant_text_parts.append(t)
                            _emit("assistant", t[:400])
                        elif block.get("type") == "tool_use":
                            pending[block.get("id", "")] = (
                                block.get("name", ""), block.get("input", {}) or {})
                            _emit("tool_use", block.get("name", ""))
                elif etype == "user":
                    msg = ev.get("message", {}) or {}
                    for block in msg.get("content", []) or []:
                        if not isinstance(block, dict) or block.get("type") != "tool_result":
                            continue
                        name, args = pending.pop(block.get("tool_use_id", ""), ("tool", {}))
                        output = _tool_result_text(block.get("content"))
                        if not output:
                            continue
                        snippet = output[:_MAX_TOOL_CHARS]
                        res.tool_outputs.append((name, args, snippet))
                        if ev_len < _MAX_EVIDENCE:
                            res.evidence += snippet + "\n"
                            ev_len += len(snippet) + 1
                        _emit("tool_result", f"{name} → {len(snippet)} 字符")
                        if on_evidence is not None:
                            try:
                                on_evidence(name, args, snippet)
                            except Exception:  # noqa: BLE001
                                pass
                elif etype == "result":
                    res.final_text = ev.get("result", "") or ""
                    res.num_turns = int(ev.get("num_turns", 0) or 0)
                    if ev.get("is_error") or ev.get("subtype") not in (None, "success"):
                        res.is_error = True
        except Exception as e:  # noqa: BLE001
            _emit("error", f"stdout 消费异常: {e}")
        finally:
            stdout_done.set()

    threading.Thread(target=_drain_stderr, daemon=True).start()
    threading.Thread(target=_consume_stdout, daemon=True).start()

    timed_out = False
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
        proc.wait(timeout=session_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=15)
        except Exception:  # noqa: BLE001
            pass
        res.error = "会话超时（长会话的正常降级）"
    except Exception as e:  # noqa: BLE001
        res.error = f"communicate 失败: {e}"
    finally:
        # 等待 stdout 线程把剩余事件消费完
        stdout_done.wait(timeout=10)

    stderr = "".join(stderr_buf)
    if timed_out:
        _emit("console", f"[engine] 已达 {session_seconds}s 会话上限，已终止")

    if transcript_path:
        try:
            os.makedirs(os.path.dirname(transcript_path) or ".", exist_ok=True)
            with open(transcript_path, "w", encoding="utf-8") as tf:
                tf.write("=== TASK PROMPT ===\n" + prompt + "\n=== STREAM-JSON (raw) ===\n")
                tf.write("\n".join(raw_stdout))
                if stderr_buf:
                    tf.write("\n=== STDERR ===\n" + "".join(stderr_buf)[:4000])
        except Exception:  # noqa: BLE001
            pass

    if not res.num_turns:
        res.num_turns = assistant_turns
    if not res.final_text:
        res.final_text = "\n".join(assistant_text_parts).strip()
    if (not res.final_text) and stderr:
        res.error = (res.error + " | " if res.error else "") + f"stderr: {stderr[:400]}"

    res.findings = extract_findings(res.final_text)
    res.handoff = extract_handoff(res.final_text)
    return res


def _tool_result_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(content)