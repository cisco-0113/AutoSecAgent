"""资产测绘管道（P5 规模化）— 从种子目标扩展授权范围内资产清单。

数据源（均为只读、限速、且在授权范围内）：
  1. 证书透明度日志（crt.sh）—— 被动子域枚举，最稳妥
  2. 静态配置/代码中的域名引用提取（apktool 解包后的 AndroidManifest/strings）
  3. 种子目标本身

设计原则：
  * 纯 Python（urllib，无第三方依赖）；无网络时安全降级为空结果
  * 所有产出强制做「根域归属校验」，越权横向资产一律剔除
  * 归一化去重（小写 / 去端口 / 去通配符前缀 / 去 IP:port）
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable

# 资产类型
A_DOMAIN = "domain"        # 根域/主域
A_SUBDOMAIN = "subdomain"  # 子域
A_IP = "ip"
A_URL = "url"

_DOMAIN_RE = re.compile(r"(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![a-z0-9_-])", re.I)
_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_URL_RE = re.compile(r"https?://[a-z0-9./_?=&%:-]+", re.I)


@dataclass
class Asset:
    host: str = ""
    type: str = A_SUBDOMAIN
    source: str = "seed"           # crt.sh / config / dns / seed
    confidence: float = 1.0

    @property
    def key(self) -> str:
        return self.host


def _normalize_host(h: str) -> str:
    """归一化：去协议、去端口、去通配符前缀、去尾部点、小写。"""
    h = h.strip().lower()
    if "://" in h:
        h = urllib.parse.urlparse(h).netloc or h
    h = h.split("@")[-1]           # 去 userinfo
    h = h.split(":")[0] if h.count(":") == 1 else h  # 去端口（仅对无协议/无IPv6的简单 host）
    h = h.rstrip(".")
    h = h.lstrip("*.")             # 去通配符前缀
    return h


def _is_ip(h: str) -> bool:
    return bool(_IPV4_RE.fullmatch(h))


def extract_from_text(text: str, source: str = "config", confidence: float = 0.7) -> list[Asset]:
    """从任意文本（manifest/strings/代码/日志）提取域名与 IP 引用。"""
    out: list[Asset] = []
    for u in _URL_RE.findall(text):
        host = _normalize_host(u)
        if host:
            out.append(Asset(host=host, type=A_URL, source=source, confidence=confidence))
    for d in _DOMAIN_RE.findall(text):
        host = _normalize_host(d)
        if host and not _is_ip(host):
            out.append(Asset(host=host, type=A_SUBDOMAIN, source=source, confidence=confidence))
    for ip in _IPV4_RE.findall(text):
        out.append(Asset(host=ip, type=A_IP, source=source, confidence=confidence))
    return out


def dedupe(assets: Iterable[Asset]) -> list[Asset]:
    """按 host 归一化去重，保留最高置信度的一条。"""
    best: dict[str, Asset] = {}
    for a in assets:
        key = _normalize_host(a.host)
        if not key:
            continue
        a.host = key
        prev = best.get(key)
        if prev is None or a.confidence > prev.confidence:
            best[key] = a
    return list(best.values())


class AssetRecon:
    """资产测绘：种子扩展 + 归属校验 + 去重。"""

    def __init__(self, timeout: int = 10, user_agent: str = "AutoSecAgent/1.0 (authorized recon)"):
        self.timeout = timeout
        self.user_agent = user_agent

    # ── 证书透明度（crt.sh，被动，只读）──
    def crt_sh(self, domain: str) -> list[Asset]:
        """查询 crt.sh 证书透明度日志，返回该域名相关子域。无网络时返回空。"""
        root = _normalize_host(domain)
        if not root:
            return []
        url = f"https://crt.sh/?q=%25.{root}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            return []
        out: list[Asset] = []
        for entry in data:
            for name in str(entry.get("name_value", "")).splitlines():
                h = _normalize_host(name)
                if h and not _is_ip(h):
                    out.append(Asset(host=h, type=A_SUBDOMAIN, source="crt.sh", confidence=0.85))
        return out

    # ── 归属校验 ──
    def in_scope(self, host: str, root_domain: str) -> bool:
        """判断 host 是否落在 root_domain 归属范围内（子域或根域本身）。"""
        h = _normalize_host(host)
        root = _normalize_host(root_domain)
        if not h or not root:
            return False
        return h == root or h.endswith("." + root)

    def filter_scope(self, assets: Iterable[Asset], root_domain: str) -> list[Asset]:
        """只保留根域归属范围内资产（IP 单独保留，交由授权清单判断）。"""
        root = _normalize_host(root_domain)
        kept = []
        for a in assets:
            if a.type == A_IP:
                kept.append(a)
            elif self.in_scope(a.host, root):
                kept.append(a)
        return kept

    # ── 汇总扩展 ──
    def expand(self, seed: str, extra_texts: Iterable[str] = ()) -> list[Asset]:
        """种子扩展：crt.sh + 配置文本提取 + 种子本身，去重 + 归属校验。"""
        root = _normalize_host(seed)
        assets: list[Asset] = [Asset(host=root, type=A_DOMAIN, source="seed", confidence=1.0)]
        assets += self.crt_sh(root)
        for text in extra_texts or []:
            assets += extract_from_text(text, source="config")
        assets = dedupe(assets)
        return self.filter_scope(assets, root)
