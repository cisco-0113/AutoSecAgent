"""速率限制 + 代理池（P6 质量安全）— 请求治理，避免触发目标限流/封禁。

对齐 safety.py 的「限速限次」硬约束，把它工程化为可复用的组件：
  * RateLimiter      —— 最小间隔节流（两次请求间隔 ≥ 1/rps），线程安全
  * ProxyPool        —— 代理地址池，轮换 + 失效标记，避免单 IP 被封
  * RequestThrottle  —— 组合两者，供 Web 扫描/差分重放调用：
                        before_request() 等待并返回可用代理，report_failure() 标记失效

纯标准库，无第三方依赖，可独立测试。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


class RateLimiter:
    """最小间隔节流器（请求/秒）。"""

    def __init__(self, rps: float = 1.0, burst: int = 1):
        # burst 保留语义：连续 burst 次可瞬时发出，之后按 rps 节流
        self.min_interval = 1.0 / max(float(rps), 0.001)
        self.burst = max(1, int(burst))
        self._tokens = float(self.burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def wait(self) -> float:
        """阻塞直到可发下一个请求，返回实际等待秒数（节流核心）。"""
        with self._lock:
            now = time.monotonic()
            self._tokens = min(float(self.burst), self._tokens + (now - self._last) / self.min_interval)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            need = (1.0 - self._tokens) * self.min_interval
            self._tokens = 0.0
        time.sleep(need)
        return need

    def remaining_seconds(self) -> float:
        """不阻塞，返回距离下一次可发请求还需等待的秒数。"""
        with self._lock:
            now = time.monotonic()
            tokens = min(float(self.burst), self._tokens + (now - self._last) / self.min_interval)
            if tokens >= 1.0:
                return 0.0
            return (1.0 - tokens) * self.min_interval


class ProxyPool:
    """代理地址池：轮换 + 失效标记。"""

    def __init__(self, proxies: Optional[list[str]] = None):
        self.proxies: list[str] = list(proxies or [])
        self._bad: set[str] = set()
        self._i = 0
        self._lock = threading.Lock()

    def next(self) -> Optional[str]:
        """返回下一个可用代理（轮换），无可用代理返回 None（直连）。"""
        with self._lock:
            good = [p for p in self.proxies if p not in self._bad]
            if not good:
                return None
            p = good[self._i % len(good)]
            self._i += 1
            return p

    def mark_bad(self, proxy: str) -> None:
        """标记代理失效（连接失败/被拒），后续轮换跳过。"""
        with self._lock:
            self._bad.add(proxy)

    def has_available(self) -> bool:
        return any(p not in self._bad for p in self.proxies)

    def __len__(self) -> int:
        return len([p for p in self.proxies if p not in self._bad])


@dataclass
class RequestThrottle:
    """请求治理门面：限速 + 代理轮换。"""

    rps: float = 1.0
    proxies: Optional[list[str]] = None
    _limiter: RateLimiter = field(init=False)
    _pool: ProxyPool = field(init=False)

    def __post_init__(self):
        self._limiter = RateLimiter(rps=self.rps)
        self._pool = ProxyPool(self.proxies)

    def before_request(self) -> Optional[str]:
        """发起请求前调用：节流等待，返回可用代理（None=直连）。"""
        self._limiter.wait()
        return self._pool.next()

    def report_failure(self, proxy: Optional[str]) -> None:
        """请求失败（连接级）时标记代理失效。"""
        if proxy:
            self._pool.mark_bad(proxy)

    def remaining_seconds(self) -> float:
        return self._limiter.remaining_seconds()
