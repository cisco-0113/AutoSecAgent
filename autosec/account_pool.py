"""账号池（P5 规模化）— 测试账号管理，支撑 Web 差分验证与批量任务。

背景：逻辑漏洞（idor-api / auth-bypass / priv-escalation）的差分验证需要
「属主账号 vs 攻击者账号 / 管理员 vs 低权 / 有凭证 vs 匿名」成对账号。
账号池负责统一管理这些测试账号的生命周期，避免每次硬编码、避免账号混用。

能力：
  1. 从 YAML 加载账号池（角色 / 凭证 / 目标域）
  2. acquire(role) 获取空闲账号；release 归还；mark_invalid 标记失效
  3. pick_pair(role_a, role_b) 差分配对（同 target 优先）
  4. render_for_prompt() 把可用账号注入子代理提示词（凭证脱敏）
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

# 标准角色（用于差分验证三模式）
ROLE_OWNER = "owner"          # 数据属主（被测方自己的账号）
ROLE_ATTACKER = "attacker"    # 攻击者（跨账号越权验证）
ROLE_ADMIN = "admin"          # 管理员（垂直越权对照）
ROLE_LOWPRIV = "lowpriv"      # 低权用户（垂直越权验证）
ROLE_ANON = "anon"            # 匿名（未授权访问验证）

_KNOWN_ROLES = {ROLE_OWNER, ROLE_ATTACKER, ROLE_ADMIN, ROLE_LOWPRIV, ROLE_ANON}


@dataclass
class Account:
    """一个测试账号。"""
    id: str = ""
    role: str = ""                 # owner/attacker/admin/lowpriv/anon
    username: str = ""
    credential: str = ""           # token/cookie/password（存储时建议脱敏或走 .env）
    target: str = ""               # 归属目标域（差分配对同 target 优先）
    status: str = "available"      # available / in_use / invalid
    note: str = ""
    acquired_at: float = 0.0
    ts: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        """凭证脱敏指纹（日志/提示词用，不含明文）。"""
        import hashlib
        if not self.credential:
            return "(空)"
        return hashlib.sha256(self.credential.encode("utf-8")).hexdigest()[:8]


class AccountPool:
    """账号池（内存态 + 可选 YAML 持久化）。"""

    def __init__(self, pool_file: str | Path | None = None):
        self.accounts: list[Account] = []
        self.pool_file = Path(pool_file) if pool_file else None
        if self.pool_file and self.pool_file.is_file():
            self.load(self.pool_file)

    # ── 加载 ──
    def load(self, path: str | Path) -> int:
        """从 YAML 加载账号池。格式：
        accounts:
          - id: u1
            role: owner
            username: a@b.com
            credential: <token>       # 敏感，建议通过环境变量注入
            target: api.example.com
        """
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw = data.get("accounts", data if isinstance(data, list) else [])
        n = 0
        for item in raw or []:
            if not isinstance(item, dict):
                continue
            acc = Account(
                id=str(item.get("id", "")),
                role=str(item.get("role", "")).lower(),
                username=str(item.get("username", "")),
                credential=str(item.get("credential", "")),
                target=str(item.get("target", "")),
                status=str(item.get("status", "available")),
                note=str(item.get("note", "")),
            )
            if acc.role not in _KNOWN_ROLES:
                continue
            self.accounts.append(acc)
            n += 1
        return n

    # ── 生命周期 ──
    def acquire(self, role: str, target: str = "") -> Optional[Account]:
        """获取一个空闲账号（role + target 匹配优先，其次 role，最后任意 role）。"""
        cands = [a for a in self.accounts if a.status == "available"]
        for pool in (
            [a for a in cands if a.role == role and target and a.target == target],
            [a for a in cands if a.role == role],
            cands,
        ):
            if pool:
                a = pool[0]
                a.status = "in_use"
                a.acquired_at = time.time()
                return a
        return None

    def release(self, account_id: str) -> bool:
        a = self._by_id(account_id)
        if a is None:
            return False
        a.status = "available"
        a.acquired_at = 0.0
        return True

    def mark_invalid(self, account_id: str, reason: str = "") -> bool:
        """标记账号失效（被封/凭证过期），未来不再使用。"""
        a = self._by_id(account_id)
        if a is None:
            return False
        a.status = "invalid"
        a.note = reason
        return True

    # ── 差分配对 ──
    def pick_pair(self, role_a: str, role_b: str, target: str = "") -> tuple[Optional[Account], Optional[Account]]:
        """获取一对账号用于差分验证（同 target 优先），不改变状态。"""
        a = self._pick(role_a, target)
        b = self._pick(role_b, target)
        return a, b

    def _pick(self, role: str, target: str) -> Optional[Account]:
        cands = [x for x in self.accounts if x.status == "available" and x.role == role]
        for c in cands:
            if target and c.target == target:
                return c
        return cands[0] if cands else None

    def _by_id(self, account_id: str) -> Optional[Account]:
        for a in self.accounts:
            if a.id == account_id:
                return a
        return None

    # ── 状态查询 / 注入 ──
    def summary(self) -> dict[str, int]:
        from collections import Counter
        c = Counter(a.role for a in self.accounts)
        return dict(c)

    def available(self, role: str = "") -> list[Account]:
        return [a for a in self.accounts
                if a.status == "available" and (not role or a.role == role)]

    def render_for_prompt(self, target: str = "") -> str:
        """把可用账号注入子代理提示词（凭证只给指纹，防泄露进日志/报告）。"""
        av = self.available()
        if not av:
            return "（无账号池，差分验证用匿名/无凭证模式或临时注册账号）"
        lines = ["■ 测试账号池（差分验证用，凭证已脱敏，实际取值见 auth 文件）："]
        for a in av:
            scope = f" @{a.target}" if a.target else ""
            lines.append(f"  - [{a.role}] {a.id} {a.username}{scope} (cred指纹={a.fingerprint()})")
        return "\n".join(lines)

    # ── 持久化 ──
    def save(self, path: str | Path | None = None) -> None:
        p = Path(path) if path else self.pool_file
        if not p:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {"accounts": [
            {k: v for k, v in a.__dict__.items() if k not in ("acquired_at", "ts")}
            for a in self.accounts
        ]}
        p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
