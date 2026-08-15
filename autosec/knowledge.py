"""CTF 知识包整合 + 自学习知识库。

两个能力：
1. CTFKnowledge —— 把本地 ctf-skills 的 markdown 蒸馏成有界的知识点，注入子代理提示词。
   注入时明确区分「CTF 场景」与「真实攻防场景」，防止把 CTF 特有的抢 flag 逻辑
   误用于实战（授权/合规/影响面）。CTF 知识仅作为「漏洞家族识别与利用思路加速器」，
   不作为越权行为的背书。
2. SelfLearningStore —— 记录每次挖洞提取的技术/技能（JSONL），下次任务自动回灌，
   让 Agent 具备跨目标的自学习能力。
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# ── CTF 与实战场景的边界宣言（注入提示词，约束 agent 的思维定位）─────────────
_CTF_VS_REAL_FRAMING = """【场景边界 · 必读】
你是安全测试 Agent，需严格区分两类场景，CTF 知识仅用于加速「漏洞识别与利用思路」，绝不改变授权边界：

■ CTF/靶场场景（本题适用）：
  - 目标：在授权靶场内取得 flag（HTB{...} / flag{...} 等），链式利用被鼓励。
  - 环境是隔离的、可复现的、无真实用户/数据，破坏性操作（如崩溃服务）可接受并可恢复。
  - 挑战常有「解析差异 / 组件版本漏洞 / 故意留的隐藏逻辑」，需穷举并组合。

■ 真实攻防/渗透场景（仅当授权文件明确声明时）：
  - 目标：在不破坏业务、不访问无关数据、不触发告警的前提下，证明漏洞影响并输出可复现 POC。
  - 必须遵守授权范围（scope），禁止：未授权横向、DoS、破坏性写库、外泄真实用户数据。
  - 影响面评估（CVSS/资产/数据敏感性）优先于完成单次利用。

无论如何：所有动作必须落在授权范围内；对每个 finding 必须提供真实工具输出作为证据，
禁止编造。CTF 里的「抢 flag 优先」在实战切换为「可复现 POC + 影响面」优先。
"""


# ── 各攻击面 → 本地 ctf-skills 的相关知识文件（按相关性排序，前 N 个被蒸馏）────
_CATEGORY_SOURCES = {
    "web": [
        ("ctf-web", "auth-infra.md"),          # OAuth/OIDC/SAML/CORS/IdP — 本题 SAML 核心
        ("ctf-web", "auth-jwt.md"),            # JWT 篡改/弱密钥/算法混淆
        ("ctf-web", "server-side.md"),         # SSTI/SSRF/php://filter/type juggling
        ("ctf-web", "server-side-advanced.md"),# 高级 SSRF/traversal/parser 差异
        ("ctf-web", "client-side.md"),         # 缓存投毒/CSRF/XSS/请求走私
        ("ctf-web", "client-side-advanced.md"),# CSP 绕过/Unicode/规范化
        ("ctf-web", "auth-and-access.md"),     # 隐藏端点/IDOR/越权
        ("ctf-web", "field-notes.md"),         # 长文速查（SQLi/XSS/LFI/JWT/SSTI/命令注入）
        ("ctf-web", "sql-injection.md"),       # SQLi 全家桶
        ("ctf-web", "node-and-prototype.md"),  # 原型链污染/Node 攻击链
    ],
    "mobile": [
        ("ctf-reverse", "languages-platforms.md"),
        ("ctf-reverse", "tools-dynamic.md"),
    ],
    "iot": [
        ("ctf-reverse", "platforms-hardware.md"),  # 嵌入式平台/架构识别 — 固件逆向基础
        ("ctf-forensics", "signals-and-hardware.md"),  # 硬件信号/固件提取手法
        ("ctf-reverse", "field-notes.md"),         # 逆向速查（ELF/固件/架构指纹）
        ("ctf-ics", "SKILL.md"),                   # ICS/SCADA 协议（Modbus/IEC104）— 车-云通信近亲
    ],
}

# 蒸馏时的行级噪音过滤
_SKIP_LINE_RX = re.compile(
    r"(chatgpt|claude|here's|here is|note:|warp|2026|\[.*\]\(http|```|^\s*-{3,}|^\s*$|"
    r"^#|the following|please|feel free|you can|table of|contents|additional resources)", re.I
)
# 判定「值得保留」的技术行：以 -/* 开头或含关键动作词
_ACTION_RX = re.compile(
    r"(exploit|bypass|inject|poison|smuggl|travers|overwrite|decode|forge|steal|leak|"
    r"script|steal|exfil|crlf|ssrf|saml|jwt|xxe|ssti|idor|lfi|rce|deserial|prototype|"
    r"canonicaliz|normaliz|parser|race|csrf|upload|command|sql|path|header|verb|token|cookie)",
    re.I
)
_MAX_CTF_PACK = 6000          # 注入提示词的 CTF 知识包上限（字符）
_MAX_PER_FILE = 1200          # 单文件蒸馏上限
_MAX_LEARNED = 4000           # 回灌的自学习知识上限


# ── 种子经验：内置、跨会话永久回灌的已验证经验（不随运行写入/覆盖）──────────────
# 每条经验在 render() 时按 category 合并进「已验证有效」分组，做成可复用的 agent 记忆。
_SEED_ENTRIES = [
    {
        "category": "mobile",
        "title": "CTF 捕获到 flag 时 finding 必须用 class='flag'",
        "technique": "抓到完整 flag（HTB{...}/flag{...}）后，输出的 <Finding> 的 class 必须为 "
                     "'flag'，evidence 字段只放 flag 原文，不要放命令/脚本输出。系统会对 flag 类 "
                     "finding 做 strong 校验并直接判 confirmed。若标成 weak-crypto/hardcoded-secret 等"
                     "其他类别，即使拿到 flag 结构化校验也会判不达标（confirmed=0），只能靠证据兜底。",
        "tags": ["flag", "finding-format", "ctf"],
        "success": True,
    },
    {
        "category": "mobile",
        "title": "多低危发现要组合成链，按终点危害定级",
        "technique": "单个「导出组件/弱加密/硬编码密钥/不安全存储/明文流量」独立提交常被 SRC "
                     "判无危或低危（导出组件、纯反编译报告尤其会被点名不收）。正确做法是按三线追踪"
                     "把它们串成攻击者可端到端执行的链：①数据流（敏感数据从哪产生→如何加密→落盘"
                     "到哪→是否可触达）；②密钥流（key 从硬编码/assets 随包文件/明文DB/Keystore/"
                     "服务端哪来，派生材料是否随包分发或与密文同目录）；③触达面（导出组件/存储权限/"
                     "deeplink 如何无交互拿到密文与密钥）。组合成一个漏洞，class 取链的使能缺陷，"
                     "风险影响评估写链的终点危害，而非各环节单独定级。",
        "tags": ["chain", "combine", "低危组合", "定级"],
        "success": True,
    },
    {
        "category": "mobile",
        "title": "本地备份加密链：assets 派生材料 + 明文种子 + 离线 HMAC 还原",
        "technique": "OPPO com.coloros.backuprestore 本地备份的真实加密形态是 AES/CBC/PKCS5Padding，"
                     "密钥派生链可完全离线恢复：①派生种子 n() 由 assets/BackupRestoreFile 按硬编码"
                     "索引数组取字符 + assets/BackupRestoreFile_salt 拼接得到；②随机种子 r 与 IV 以"
                     "明文写在备份目录 backup_config_new.db 的 EncryptInfo 表（与密文同目录）；③最终"
                     "密钥 = HMAC-SHA256(key=r, msg=n()) 逐字节取高4位 hex（32 字符）再 UTF-8 作 "
                     "AES-256 key。攻击者仅凭 APK+备份目录即可离线解密 contact.vcf/sms.vmsg/"
                     "callrecord.xml 还原短信/通讯录/通话记录。教训：别只看 libKey.so 的 getKey() 常量"
                     "（那是克隆传输旧路径），要顺 doEncrypt 实际调用链逆到根——密钥材料「随包分发」"
                     "+「明文与密文共存」才是致命点。",
        "tags": ["chain", "backup", "aes-cbc", "hmac", "密钥派生", "offline-decrypt"],
        "success": True,
    },
]


@dataclass
class KnowledgeEntry:
    """一条可回灌的知识经验。"""
    source: str = ""            # 来源：ctf-skills / self-learned / finding
    category: str = ""          # web/mobile/iot
    title: str = ""             # 一句话技术要点
    technique: str = ""         # 详细手法
    tags: list = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    target: str = ""            # 学到的目标（自学习用）
    success: bool = True        # 该手法是否在本目标被验证有效


def _distill_file(path: Path, budget: int) -> list[str]:
    """把单个 markdown 蒸馏成 < 预算 的技术要点行列表。

    策略：保留 ##/### 标题作为技术目录；跳过 Table of Contents、代码块、锚点与
    超长行；保留非代码的短句（特别是有 Key insight 的总结句）。
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows: list[str] = []
    cur_header = ""
    chars = 0
    in_toc = False
    in_code = False
    for ln in lines:
        s = ln.rstrip()
        if not s:
            if in_toc:
                in_toc = False
            continue
        if s.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:                       # 代码块内容跳过（噪声）
            continue
        if s.startswith("##") or s.startswith("###"):
            head = s.lstrip("#").strip()
            if head.lower().startswith("table of contents") or head.lower() == "toc":
                in_toc = True
                cur_header = ""
                continue
            in_toc = False
            # 标题本身就是技术要点，直接入目录
            if cur_header and rows and not rows[-1].startswith("▸"):
                rows.append(f"▸ {cur_header}")
                chars += len(cur_header) + 3
            cur_header = head
            continue
        if s.startswith("#"):              # 顶层标题跳过
            continue
        if in_toc:
            continue
        if _SKIP_LINE_RX.search(s):
            continue
        if "](#" in s:                     # 纯锚点/链接行
            continue
        content = s.lstrip("- *•0123456789. ")
        if not content:
            continue
        # 只保留短句或关键总结（代码/长行丢弃）
        if len(s) > 200:
            continue
        if "key insight" in s.lower() or ("**" in s and len(s) < 180):
            row = f"- [{cur_header}] {content[:170]}"
        elif len(s) < 90 and _ACTION_RX.search(s):
            row = f"- [{cur_header}] {content[:170]}"
        else:
            continue
        if len(row) > chars + budget:
            break
        rows.append(row)
        chars += len(row) + 1
    if cur_header and rows and not rows[-1].startswith("▸"):
        rows.append(f"▸ {cur_header}")
    return rows


class CTFKnowledge:
    """加载本地 ctf-skills，蒸馏出有界的 CTF 知识包。"""

    def __init__(self, skill_dir: str | Path | None = None):
        self.skill_dir = Path(skill_dir) if skill_dir else None
        self._pack_cache: dict[str, str] = {}

    def is_available(self) -> bool:
        return self.skill_dir is not None and self.skill_dir.is_dir()

    def build_pack(self, category: str) -> str:
        """为某攻击面生成注入用的 CTF 知识包（含场景边界+技术要点）。"""
        if category in self._pack_cache:
            return self._pack_cache[category]
        body = self._build_tech(category)
        pack = _CTF_VS_REAL_FRAMING + "\n\n■ 本类资产相关 CTF/利用技术速查（仅作思路加速，须验证后使用）：\n" + body
        self._pack_cache[category] = pack
        return pack

    def _build_tech(self, category: str) -> str:
        if not self.is_available():
            return "(未配置 CTF skill 目录，跳过)\n"
        srcs = _CATEGORY_SOURCES.get(category, [])
        total = 0
        parts: list[str] = []
        for rel_path, fname in srcs:
            f = self.skill_dir / rel_path / fname
            if not f.is_file():
                continue
            rows = _distill_file(f, _MAX_PER_FILE)
            if not rows:
                continue
            head = f"【{rel_path}/{fname}】"
            block = head + "\n" + "\n".join(rows)
            if total + len(block) > _MAX_CTF_PACK:
                break
            parts.append(block)
            total += len(block) + 1
        return ("\n\n".join(parts)) if parts else "(CTF 知识蒸馏为空)\n"


class SelfLearningStore:
    """自学习知识库（JSONL）。

    每次挖洞闭环后，把验证有效的技术与未遂尝试都记录下来；下次任务自动回灌，
    让 Agent 避免重复踩坑、复用有效手法。
    """

    def __init__(self, knowledge_dir: str | Path | None = None):
        if knowledge_dir is None:
            from .config import PROJECT_ROOT
            knowledge_dir = PROJECT_ROOT / "data" / "knowledge"
        self.dir = Path(knowledge_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.file = self.dir / "learned.jsonl"

    # -- 写入 ----
    def record(self, entry: KnowledgeEntry) -> None:
        try:
            with self.file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.__dict__, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def record_many(self, entries: Iterable[KnowledgeEntry]) -> int:
        n = 0
        for e in entries:
            self.record(e)
            n += 1
        return n

    # -- 读取 ----
    def load(self, limit: int = _MAX_LEARNED) -> list[KnowledgeEntry]:
        out: list[KnowledgeEntry] = []
        if not self.file.is_file():
            return out
        try:
            lines = self.file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return out
        for ln in lines:
            try:
                d = json.loads(ln)
                out.append(KnowledgeEntry(**{k: d[k] for k in d if hasattr(KnowledgeEntry, k)}))
            except (json.JSONDecodeError, TypeError):
                continue
        return out

    def render(self, category: str = "") -> str:
        """把历史经验渲染成提示词片段，按成功/失败分组。

        内置种子经验（_SEED_ENTRIES）永久并入「已验证有效」分组，保证跨会话回灌。
        """
        entries = self.load()
        if category:
            entries = [e for e in entries if not category or e.category == category]
        # 种子经验：按 category 过滤后并入（保持可复用记忆不受运行清空影响）
        seeds = [KnowledgeEntry(**d) for d in _SEED_ENTRIES
                 if not category or d.get("category") == category]
        win = [e for e in entries if e.success]
        lose = [e for e in entries if not e.success]
        buf = ["■ 自学习历史经验（跨目标复用，来自此前挖洞）："]
        buf.append(f"+ 已验证有效（{len(win) + len(seeds)} 条）：")
        for e in seeds[-6:]:
            buf.append(f"  • [种子·{e.title}] {e.technique[:160]}")
        for e in win[-12:]:
            buf.append(f"  • [{e.title}] {e.technique[:160]}")
        if lose:
            buf.append(f"- 尝试未遂/踩坑（{len(lose)} 条，避免重复）：")
            for e in lose[-8:]:
                buf.append(f"  • {e.title}: {e.technique[:140]}")
        return "\n".join(buf)


# ── 从引擎结果启发式提取自学习条目 ────────────────────────────────────────────
# 命令执行类 tool（其命令值得作为「尝试技术」记录）
_CMD_TOOL = ("Bash", "PowerShell", "python", "python3", "Terminal", "LocalShell", "cmd")
# 纯信息获取类 tool（WebSearch/WebFetch/Read/Grep/Glob/LS 等）不记为「尝试技术」——
# 它们只是看资料，不代表任何技术动作；只有真实命令执行才值得回灌
_INFO_TOOLS = {
    "WebSearch", "WebFetch", "Read", "Grep", "Glob", "LS", "GetDiagnostics",
    "TodoWrite", "OpenPreview", "CheckCommandStatus", "StopCommand",
}
# 命令内容含「技术动作信号」才值得记录（过滤纯 URL 浏览 / echo / Write-Host 等噪声）
_ACTION_CMD_RX = re.compile(
    r"(exploit|bypass|decrypt|encrypt|derive|hook|pull|push|decompile|apktool|jadx|"
    r"androguard|frida|adb|am start|am broadcast|run-as|sqlmap|nmap|ffuf|hydra|hashcat|"
    r"john|openssl|dump|extract|inject|replay|hmac|aes|cbc|gcm|keystore|\.rodata|"
    r"getKey|uiautomator|input tap|input swipe|curl .*(-d|--data|-X POST|-X PUT)|"
    r"secretkey|ivparam|secretkeyspec|base64|strings|elftools|capstone)",
    re.I,
)
# 纯脚本模板语句（无技术动作、只是脚本骨架）——即便命中也丢弃
_SCRIPT_NOISE_RX = re.compile(
    r"(StreamReader|GetResponseStream|GetRequestStream|New-Object|Select-Object|"
    r"function |if\{|Write-Output|Write-Host|System\.Text\.Encoding|GetResponse|"
    r"echo |Set-Content|Out-File|ForEach-Object|add-type)",
    re.I,
)
# 可组合成链的静态/配置类类别（出现 ≥2 个时提示组合链）
_CHAINABLE_CLASSES = {
    "hardcoded-secret", "weak-crypto", "insecure-storage", "exported-component",
    "cleartext-traffic", "crypto-key-extract", "signature-key-leak",
    "runtime-cred", "weak-cert-validation", "ssl-unpinning",
}


def learn_from_result(surface: str, target: str,
                      findings: list, handoff: str, evidence: str = "",
                      tool_outputs: list | None = None) -> list[KnowledgeEntry]:
    """挖洞闭环后，把 findings + handoff + 工具调用提炼为结构化知识经验。

    信号驱动原则（只记「值得记忆」的，杜绝侦察噪声回灌污染）：
      1. 每个 finding → 一条 success 经验（漏洞本身是最硬的经验）
      2. handoff → 一条失败经验（遗留状态/下一步）
      3. 组合链检测：≥2 个可组合类别 finding → 一条「建议组合成链」经验
      4. 工具调用：仅记录「命令执行类 tool + 输出非空 + 命中技术动作信号 + 非脚本噪声」
         的命令，标记 success=False（尝试过，供未来避免重复无效劳动）
      5. 侦察兜底：仅当无任何产出时才记一条占位，避免自学习静默
    """
    out: list[KnowledgeEntry] = []

    # 1) finding → success 经验
    for f in findings or []:
        title = f"{f.vuln_class or 'vuln'}@{f.location or '?'}".strip()
        out.append(KnowledgeEntry(
            source="self-learned", category=surface, target=target,
            title=title, technique=f.description or f.raw,
            tags=[f.vuln_class] if f.vuln_class else [],
            success=True,
        ))

    # 2) handoff → 失败经验
    if handoff:
        out.append(KnowledgeEntry(
            source="self-learned", category=surface, target=target,
            title="本目标遗留状态/handoff", technique=handoff[:400],
            tags=["handoff"], success=False,
        ))

    # 3) 组合链检测：多个可组合类别同现 → 提示串链
    chainable = {f.vuln_class for f in (findings or [])
                 if f.vuln_class in _CHAINABLE_CLASSES}
    if len(chainable) >= 2:
        out.append(KnowledgeEntry(
            source="self-learned", category=surface, target=target,
            title="多个可组合低危类别同现，建议串成攻击链",
            technique="本目标同时出现 " + "、".join(sorted(chainable)) +
                      "，这些静态/配置类漏洞独立定级低，但可能同属一条攻击链。"
                      "尝试按「数据流+密钥流+触达面」三线追踪组合成端到端可执行的链，"
                      "按链的终点危害定级，而非各自独立提交。",
            tags=["chain-hint", *sorted(chainable)], success=False,
        ))

    # 4) 工具调用 → 仅记录有价值的技术动作命令
    seen: set[str] = set()
    for tool, args, output in (tool_outputs or []):
        if tool in _INFO_TOOLS:
            continue
        if tool not in _CMD_TOOL:
            continue
        # 输出为空说明命令没真正产生结果，跳过
        if not (output or "").strip():
            continue
        argstr = ""
        if isinstance(args, dict):
            items = [str(v) for v in args.values() if isinstance(v, str)]
            argstr = " ".join(items)
        elif isinstance(args, str):
            argstr = args
        argstr = argstr.strip()
        for c in re.split(r"[;\n]", argstr):
            c = c.strip()
            if not (12 <= len(c) <= 400):
                continue
            if not _ACTION_CMD_RX.search(c):
                continue
            if _SCRIPT_NOISE_RX.search(c):
                continue
            key = c[:120]
            if key in seen:
                continue
            seen.add(key)
            out.append(KnowledgeEntry(
                source="tool-trace", category=surface, target=target,
                title=f"尝试技术: {c[:40]}…" if len(c) > 40 else f"尝试技术: {c}",
                technique=c, tags=["tool-trace"],
                success=False,   # 未经验证，作为「尝试过」的经验
            ))

    # 5) 侦察兜底：无任何产出才记一条，避免自学习静默
    if not out and (evidence or tool_outputs):
        out.append(KnowledgeEntry(
            source="self-learned", category=surface, target=target,
            title=f"{target} 侦察完成但未产出漏洞", technique=evidence[:200],
            tags=["recon"], success=False,
        ))
    return out