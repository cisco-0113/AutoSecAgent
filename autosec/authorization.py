"""授权声明校验。

AutoSecAgent 的合规红线：自动化能力仅在明确授权范围内使用。
本模块在每次运行开始时强制校验授权声明，未授权则拒绝启动。
授权声明文件为 YAML/JSON，包含授权范围字段。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ── 包名 vs 域名 判别（与 classifier 口径一致）─────────────────────────────────
_MOBILE_PACKAGE_RE = re.compile(r"^(com|org|cn|io|net)\.[a-z0-9_.]{2,}$", re.I)
_STRONG_TLD = {"com", "net", "org", "cn", "edu", "gov", "mil", "int"}
# 从路径/含后缀字符串中提取纯包名（如 D:\...\com.coloros.backuprestore.apk）
_PACKAGE_IN_TEXT_RE = re.compile(
    r"(?<![a-z0-9_.])(?:com|org|cn|io|net)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+(?![a-z0-9_])", re.I)


def _looks_like_package(t: str) -> bool:
    """判断字符串是否为包名（与 classifier 同一套判别）。"""
    if not _MOBILE_PACKAGE_RE.match(t):
        return False
    segs = t.split(".")
    if len(segs) < 3:
        return False
    return segs[-1].lower() not in _STRONG_TLD


def _looks_like_package_rule(x: str) -> bool:
    """判断授权条目是否为「包名规则」（比目标包名更宽松）。

    允许三种形态：
      - 完整包名  com.oppo.usercenter
      - 段前缀    com.oppo（两段即可，匹配其下所有子包）
      - 段通配    com.oppo.*（含 * 段）
    末段为强 TLD 的（com.example.com）仍判为域名，不落入包名规则。
    """
    if "*" in x:
        return bool(re.match(r"^(com|org|cn|io|net)(\.[a-z0-9_*]+){1,}$", x, re.I))
    if not _MOBILE_PACKAGE_RE.match(x):
        return False
    segs = x.split(".")
    if len(segs) < 2:
        return False
    return segs[-1].lower() not in _STRONG_TLD


def _extract_package(text: str) -> str:
    """从可能含路径/后缀的字符串中提取纯包名，取不到返回空串。"""
    m = _PACKAGE_IN_TEXT_RE.search(text)
    if not m:
        return ""
    pkg = m.group(0)
    # 去掉尾部 .apk/.ipa 等后缀（若被误纳入段）
    pkg = re.sub(r"\.(apk|ipa)$", "", pkg, flags=re.I)
    return pkg


def _package_covers(pkg: str, rule: str) -> bool:
    """包名段级精确匹配。

    - 规则含 `*`：逐段匹配，`*` 匹配任意单段，段数必须相等
      （com.oppo.* 匹配 com.oppo.usercenter，不匹配 com.oppo.a.b）
    - 规则不含 `*`：规则是目标包的段前缀
      （com.oppo 匹配 com.oppo.usercenter；com.oppo.usercenter 精确匹配，
        绝不匹配 com.oppo.usercenter2）
    """
    ps, rs = pkg.split("."), rule.split(".")
    if any(r == "*" for r in rs):
        if len(ps) != len(rs):
            return False
        return all(r == "*" or p == r for p, r in zip(ps, rs))
    if len(rs) > len(ps):
        return False
    return ps[:len(rs)] == rs


def _segment_contains(text: str, rule: str) -> bool:
    """rule 是否作为「点号边界的完整段」出现在 text 中（防子串误匹配）。"""
    return bool(re.search(r"(?<![a-z0-9_.])" + re.escape(rule) + r"(?![a-z0-9_])", text))


@dataclass
class Authorization:
    """授权声明。"""

    file: str = ""
    authorized: bool = False
    scope: str = ""                 # 授权范围描述
    targets: list[str] = field(default_factory=list)   # 授权目标清单
    start: str = ""
    end: str = ""
    notes: str = ""

    @property
    def ok(self) -> bool:
        return self.authorized

    def covers(self, target: str) -> bool:
        """校验目标是否在授权目标清单内。

        匹配优先级（高->低）：
          1. 通配符域名 `*.oppo.com` -> 后缀匹配（含根域 oppo.com 本身），
             精确限定域名归属，避免 `evil-oppo.com` 误匹配 `oppo.com`
          2. 包名段级精确匹配：规则 `com.oppo` 匹配 `com.oppo.usercenter`（段前缀），
             但不匹配 `com.oppo.usercenter2`；规则含 `*` 则段级通配
             （com.oppo.* 匹配 com.oppo.usercenter，不匹配 com.oppo.a.b）
          3. 规则作为「点号边界完整段」出现在目标内（覆盖 APK 路径嵌包名等场景）
          4. 未限制清单 -> 视为全授（由 scope 兜底）
        """
        if not self.targets:
            return True
        t = target.lower().strip()
        if not t:
            return False
        for x in self.targets:
            x = str(x).lower().strip()
            if not x:
                continue
            # 1) 通配符域名：*.oppo.com -> ".oppo.com" 后缀 / "oppo.com" 根域
            if x.startswith("*."):
                suffix = x[1:]          # ".oppo.com"
                root = x[2:]            # "oppo.com"
                if t == root or t.endswith(suffix):
                    return True
                continue
            # 2) 包名段级匹配（规则本身像包名时）
            if _looks_like_package_rule(x):
                pkg = _extract_package(t)
                if pkg and _package_covers(pkg, x):
                    return True
                if _looks_like_package(t) and _package_covers(t, x):
                    return True
                # 3) 非包名 target（完整路径等）按点号边界完整段兜底，防子串误匹配
                if _segment_contains(t, x):
                    return True
                continue
            # 4) 域名/IP/URL/路径等非包名规则：点号边界包含匹配，杜绝子串误匹配
            if t == x:
                return True
            if "." in x:
                # 域名层级包含：oppo.com ⊂ www.oppo.com（点号边界后缀）
                if t.endswith("." + x) or x.endswith("." + t):
                    return True
                # URL/路径中嵌域名：点号边界完整段匹配（防 com.example.com 误配 .com2）
                if _segment_contains(t, x):
                    return True
                continue   # 含点号规则只用点号边界匹配，不落子串
            # 不含点号的普通片段（纯路径前缀等）保留子串匹配
            if t in x or x in t:
                return True
        return False


def load_authorization(path: str | Path) -> Authorization:
    """从 YAML/JSON 文件加载授权声明。"""
    p = Path(path)
    if not p.is_file():
        return Authorization(file=str(path), authorized=False, notes="授权文件不存在")

    text = p.read_text(encoding="utf-8")
    data: dict[str, Any] = {}
    if p.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = yaml.safe_load(text) or {}

    return Authorization(
        file=str(path),
        authorized=bool(data.get("authorized", data.get("authorize", False))),
        scope=str(data.get("scope", "")),
        targets=[str(x) for x in data.get("targets", [])],
        start=str(data.get("start", "")),
        end=str(data.get("end", "")),
        notes=str(data.get("notes", "")),
    )


def check(required: bool, auth_file: str, target: str) -> tuple[bool, str]:
    """执行授权校验。返回 (是否通过, 说明)。"""
    if not required:
        return True, "授权校验已关闭 (auth_required=false)"

    if not auth_file:
        return False, "未提供授权声明文件 (--auth)。AutoSecAgent 默认拒绝无授权运行。"

    auth = load_authorization(auth_file)
    if not auth.ok:
        return False, f"授权声明未通过: {auth.notes or 'authorized 字段为 false'}"

    if not auth.covers(target):
        return False, f"目标不在授权范围内: {target}"

    return True, f"授权校验通过 (scope: {auth.scope or '见授权文件'})"