"""配置加载与默认值。

AutoSecAgent 配置来源优先级（低->高）：
  1. 包内默认值 (Config.DEFAULTS)
  2. 项目根 config.yaml
  3. 环境变量 (AUTOSEC_*)
  4. CLI 参数
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── 执行引擎 provider 预设（Anthropic 兼容端点，借鉴 hxbai）────────────────────────
_ENGINE_PRESETS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-flash",
        "small_fast_model": "deepseek-v4-flash",
    },
    "deepseek-1m": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-pro[1m]",
        "small_fast_model": "deepseek-v4-flash",
        "auto_compact_window": "786432",
        "api_timeout_ms": "3000000",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.2",
        "small_fast_model": "glm-5.2",
    },
    "glm-1m": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.2[1m]",
        "small_fast_model": "glm-5.2",
        "auto_compact_window": "1000000",
        "api_timeout_ms": "3000000",
    },
    "baidu-glm": {
        "base_url": "https://agent-awd.baidu.com",
        "model": "glm-5.2-agent-chanllenge",
        "small_fast_model": "glm-5.2-agent-chanllenge",
        "api_timeout_ms": "300000",
    },
}


def _load_dotenv() -> None:
    """轻量加载项目根 .env（避免额外依赖 fail-fast）。仅在 AUTO 未设置时生效。"""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("'\"")
        if k and os.environ.get(k) is None:
            os.environ[k] = v


@dataclass
class Config:
    """AutoSecAgent 运行时配置。"""

    # 目标
    target: str = ""
    # 授权声明文件路径（授权范围硬校验）
    auth_file: str = ""
    # 授权声明是否为必填（P0 默认强制，防止未授权使用）
    auth_required: bool = True
    # 攻击面覆盖范围，默认全部
    attacksurfaces: list[str] = field(default_factory=lambda: ["web", "mobile", "iot"])

    # 执行引擎（Claude Code 桥接）
    engine: str = "claude-code"
    engine_cmd: str = "claude"
    engine_provider: str = "deepseek"    # deepseek | deepseek-1m | glm | glm-1m
    engine_api_key: str = ""             # AUTOSEC_ENGINE_API_KEY
    engine_base_url: str = ""            # 显式覆盖端点（默认由 provider 推导）
    engine_model: str = ""               # 显式覆盖模型（默认由 provider 推导）
    max_turns: int = 120                 # 单子代理引擎轮数总预算（跨续接会话累计）
    session_seconds: int = 1800           # 单子代理挂钟总预算（跨续接会话累计）
    max_continue_rounds: int = 2          # 未达标时的续接会话上限（总会话 = 1 + 该值）

    # CTF 知识整合 + 自学习
    ctf_skill_dir: str = ""              # 本地 ctf-skills 目录（为空则跳过 CTF 知识注入）
    knowledge_dir: str = ""              # 自学习知识库目录（默认 data/knowledge）
    ctf_mode: bool = False               # 是否以 CTF/靶场模式运行（注入场景边界与 flag 提取）

    # 止损（借鉴 hxbai stoploss）
    time_budget_sec: int = 900          # 单目标总时间上限
    session_budget: int = 30            # 单目标工具会话上限
    no_output_rounds: int = 5           # 连续无产出轮数上限
    target_budget_sec: int = 3600       # 目标级预算（新增维）

    # 校验门（借鉴 hxbai verify）
    verify_enabled: bool = True
    require_poc: bool = True            # confirmed 必须可复现 POC

    # 存储
    data_dir: str = "data"
    report_dir: str = "reports"

    # 工具
    tool_dir: str = "tools"
    tool_timeout: int = 120             # 单工具默认超时(秒)
    tool_max_output_chars: int = 20000  # 输出超限 spill 落盘阈值

    # P5 规模化
    account_pool_file: str = ""         # 测试账号池 YAML（Web 差分验证用）
    batch_state_file: str = ""          # 批量任务状态 JSONL（去重/续跑）

    # P6 质量安全
    negation_enabled: bool = False      # 否定门接 LLM（需 engine ready；未就绪自动降级）
    ratelimit_rps: float = 1.0          # 请求速率限制（请求/秒）
    proxy_list: list[str] = field(default_factory=list)   # 代理池地址列表

    @classmethod
    def defaults(cls) -> "Config":
        return cls()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Config":
        cfg = cls.defaults()
        for k, v in d.items():
            if hasattr(cfg, k) and v is not None:
                setattr(cfg, k, v)
        return cfg

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "Config":
        """按优先级合并配置。"""
        _load_dotenv()  # 先加载 .env，再读环境变量
        cfg = cls.defaults()

        # 1) config.yaml
        path = Path(config_path) if config_path else PROJECT_ROOT / "config.yaml"
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            cfg = cls.from_dict(data)

        # 2) 环境变量 AUTOSEC_*
        for k, v in os.environ.items():
            if k.startswith("AUTOSEC_"):
                key = k[len("AUTOSEC_"):].lower()
                if hasattr(cfg, key):
                    cur = getattr(cfg, key)
                    if isinstance(cur, bool):
                        setattr(cfg, key, v.lower() in ("1", "true", "yes"))
                    elif isinstance(cur, int):
                        setattr(cfg, key, int(v))
                    else:
                        setattr(cfg, key, v)

        return cfg

    def resolve_paths(self) -> None:
        """将相对路径解析为绝对路径。"""
        self.data_dir = str(PROJECT_ROOT / self.data_dir)
        self.report_dir = str(PROJECT_ROOT / self.report_dir)
        self.tool_dir = str(PROJECT_ROOT / self.tool_dir)
        # 自学习知识库默认落到 data/knowledge
        if not self.knowledge_dir:
            self.knowledge_dir = str(PROJECT_ROOT / "data" / "knowledge")
        else:
            p = Path(self.knowledge_dir)
            self.knowledge_dir = str(p if p.is_absolute() else PROJECT_ROOT / p)
        # CTF skill 目录若未显式配置，尝试本地默认位置（项目内 / 项目父目录）
        if not self.ctf_skill_dir:
            for cand in (
                PROJECT_ROOT / "ctf-skills",
                PROJECT_ROOT.parent / "ctf-skills",
            ):
                if cand.is_dir():
                    self.ctf_skill_dir = str(cand)
                    break
        # P5 账号池 / 批量状态路径解析为绝对路径
        if self.account_pool_file:
            p = Path(self.account_pool_file)
            self.account_pool_file = str(p if p.is_absolute() else PROJECT_ROOT / p)
        if self.batch_state_file:
            p = Path(self.batch_state_file)
            self.batch_state_file = str(p if p.is_absolute() else PROJECT_ROOT / p)

    def engine_env(self) -> dict:
        """构造注入 Claude Code 子会话的环境变量（Anthropic 兼容端点）。

        借鉴 hxbai：固定所有模型槽位，保证全程单模型。返回空值会被 engine 过滤。
        """
        preset = _ENGINE_PRESETS.get(self.engine_provider, _ENGINE_PRESETS["deepseek"])
        base_url = self.engine_base_url or preset["base_url"]
        model = self.engine_model or preset["model"]
        small = preset.get("small_fast_model", model)
        return {
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_AUTH_TOKEN": self.engine_api_key,
            "ANTHROPIC_API_KEY": self.engine_api_key,
            "ANTHROPIC_MODEL": model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": small,
            "ANTHROPIC_SMALL_FAST_MODEL": small,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1",
            "CLAUDE_CODE_AUTO_COMPACT_WINDOW": preset.get("auto_compact_window", ""),
            "API_TIMEOUT_MS": preset.get("api_timeout_ms", ""),
        }

    def engine_ready(self) -> tuple[bool, str]:
        """校验真实运行环境是否就绪（claude CLI + API key）。"""
        import shutil
        if not shutil.which(self.engine_cmd):
            return False, f"未找到 claude CLI ({self.engine_cmd})，请先安装并加入 PATH"
        if not self.engine_api_key:
            return False, "未配置引擎 API key（AUTOSEC_ENGINE_API_KEY / .env）"
        return True, f"引擎就绪: {self.engine_provider} @ {self.engine_base_url or '预设端点'}"