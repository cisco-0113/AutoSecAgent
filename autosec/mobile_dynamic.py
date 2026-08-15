"""移动端动态分析工作流 — 静态发现 → 运行时验证 → 证据升级。

P2 动态增强：把静态分析产出的 Finding 转化为可执行的动态验证计划，在有
frida/adb/模拟器时真正交付运行时证据（hook 输出/组件调起日志），把静态 suspected/
probable 升级为 confirmed；无设备时也产出带具体命令与预期证据的验证计划，杜绝
「动态验证缺口」空窗导致的无产出。

三个能力：
  1. probe_environment()  探测本机 frida/adb/模拟器/java 可用性
  2. build_dynamic_plan() 静态 Finding → 有优先级的动态验证计划
  3. frida_script_for()   按漏洞类别生成可直接运行的 frida JS（可落盘）
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── 动态工具探测 ───────────────────────────────────────────────────────────────
@dataclass
class DynEnv:
    """动态分析环境可用性快照。"""
    frida: bool = False
    adb: bool = False
    emulator: bool = False
    java: bool = False
    devices: list = field(default_factory=list)   # adb devices 列表（非空即有设备）
    detail: str = ""

    @property
    def ready(self) -> bool:
        """能否真正跑动态验证：frida/adb 之一 + 至少一台设备。"""
        return (self.frida or self.adb) and bool(self.devices)

    def capability_note(self) -> str:
        if self.ready:
            return f"动态就绪 frida={self.frida} adb={self.adb} 设备={self.devices}"
        if self.frida or self.adb:
            return f"已装工具但无设备连接（frida={self.frida} adb={self.adb}）→ 无法实跑，输出验证计划"
        return "无 frida/adb 动态工具 → 仅输出验证计划与手工步骤"


def _find_adb() -> str:
    """定位 adb 可执行文件：PATH 优先，其次项目内 platform-tools（实战常用）。"""
    p = shutil.which("adb")
    if p:
        return p
    # 项目内工具目录（tools/mobile/bin/platform-tools/adb.exe）
    candidates = [
        Path(__file__).resolve().parent.parent / "tools" / "mobile" / "bin"
        / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb"),
        Path(__file__).resolve().parent.parent / "tools" / "mobile" / "bin" / "adb",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    # ANDROID_HOME / ANDROID_SDK_ROOT 下的 platform-tools
    for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env_name)
        if root:
            c = Path(root) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
            if c.is_file():
                return str(c)
    return ""


def probe_environment(python: str = "python") -> DynEnv:
    """探测动态分析工具链可用性（不抛异常，任何缺失都降级）。"""
    env = DynEnv()
    env.java = shutil.which("java") is not None
    env.frida = shutil.which("frida") is not None or shutil.which("frida-ps") is not None
    env.adb = bool(_find_adb())
    env.emulator = shutil.which("emulator") is not None
    if env.adb:
        adb = _find_adb()
        try:
            r = subprocess.run([adb, "devices"], capture_output=True, text=True,
                               timeout=15, check=False)
            for ln in r.stdout.splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("List") and not ln.lower().startswith("*"):
                    name = ln.split()[0] if ln.split() else ""
                    state = ln.split()[1] if len(ln.split()) > 1 else ""
                    if state == "device":
                        env.devices.append(name)
        except Exception:  # noqa: BLE001
            env.devices = []
    env.detail = env.capability_note()
    return env


# ── Frida hook 脚本模板（按漏洞类别）──────────────────────────────────────────
# placeholder 用 {PKG}、{FN}、{CIPHER} 等，由 frida_script_for() 替换。
_FRIDA_TEMPLATES = {
    "ssl-unpinning": """\
Java.perform(function () {
    // Universal SSL pinning bypass（覆盖 OkHttp/TrustManager/WebView）
    ['SSLContext', 'TrustManagerImpl', 'X509TrustManagerExtensions'].forEach(function(n){
        try { Java.use(n); } catch(e){ return; }
    });
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation =
            function(a,b,c){ console.log('[SSL] SSLContext.init hooked'); return this.init(a,null,c); };
    } catch(e){ console.log('[SSL] ' + e); }
    try {
        var OkHttp = Java.use('okhttp3.OkHttpClient');
        console.log('[SSL] OkHttp present');
    } catch(e){ console.log('[SSL] no okhttp3'); }
    try {
        var X509 = Java.use('javax.net.ssl.X509TrustManager');
        var MyTrust = Java.registerClass({ name:'com.demo.TrustAll', implements:[X509],
            methods:{ checkClientTrusted:function(c,a){console.log('[SSL] checkClientTrusted');},
                      checkServerTrusted:function(c,a){console.log('[SSL] VERIFY_BYPASSED');},
                      getAcceptedIssuers:function(){return [];} } });
        console.log('[SSL] TrustAll registered (VERIFY_BYPASSED 可作证据)');
    } catch(e){ console.log('[SSL] trustManager reg: ' + e); }
});
""",
    "crypto-key-extract": """\
Java.perform(function () {
    // 提取加密原语使用的密钥/IV/算法（覆盖 Cipher/SecretKeySpec/IvParameterSpec）
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.init.overload('int','java.security.Key').implementation = function(m,k){
            console.log('[CRYPTO] init mode=' + m + ' key=' + k);
            if (k && k.getEncoded) {
                var b = k.getEncoded();
                console.log('[CRYPTO] KEY_HEX=' + _hex(b));
            }
            return this.init(m,k);
        };
        Cipher.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec')
            .implementation = function(m,k,spec){
                console.log('[CRYPTO] init(mode,key,spec) spec=' + spec);
                if (spec && spec.getIV) console.log('[CRYPTO] IV_HEX=' + _hex(spec.getIV()));
                return this.init(m,k,spec);
            };
    } catch(e){ console.log('[CRYPTO] ' + e); }
    function _hex(b){ if(!b) return ''; var s=''; for(var i=0;i<b.length;i++){
        s += ('0'+((b[i]&0xff).toString(16))).slice(-2); } return s; }
});
""",
    "runtime-cred": """\
Java.perform(function () {
    // 抓取登录/鉴权令牌：SharedPreferences 写入 + HTTP 头（Authorization/Bearer）
    try {
        var SP = Java.use('android.content.SharedPreferences$Editor');
        SP.putString.overload('java.lang.String','java.lang.String').implementation =
            function(k,v){ console.log('[AUTH] SP_PUT ' + k + '=' + v); return this.putString(k,v); };
    } catch(e){}
    try {
        var Req = Java.use('okhttp3.Request$Builder');
        Req.header.overload('java.lang.String','java.lang.String').implementation =
            function(k,v){ if(/auth|token|bearer/i.test(k)||/bearer [A-Za-z0-9._-]+/i.test(v))
                console.log('[AUTH] HEADER ' + k + '=' + v); return this.header(k,v); };
    } catch(e){ console.log('[AUTH] no okhttp Request'); }
});
""",
    "class-dump": """\
Java.perform(function () {
    // 枚举已加载类，定位目标类路径（用于导出组件/深链注入前的类定位）
    Java.enumerateLoadedClasses({ onMatch: function(name){
        if (name.indexOf('{PKG}') !== -1 || /{FN}/i.test(name)) console.log('[CLASS] ' + name);
    }, onComplete: function(){} });
});
""",
}

# 类别 → 使用哪个模板 + 期望证据标识（供 oracle 判定）
_CRYPTO_KEYS = {"crypto-key-extract", "weak-crypto", "hardcoded-secret", "signature-key-leak"}
_AUTH_KEYS = {"runtime-cred", "login-token", "hardcoded-secret"}


@dataclass
class DynamicPlanItem:
    """一条动态验证计划。"""
    target: str            # 验证对象（组件/函数/类）
    rationale: str         # 为什么这样验证（关联静态发现）
    command: str           # 可执行命令（frida -U -f... / adb am start...）
    evidence_expected: str # 期望的运行时证据关键词（也是 oracle 匹配串）
    oracle_keys: list = field(default_factory=list)  # 命中的 verify.py oracle 类别
    script: str = ""       # 需要的 frida js（空则用 adb 命令）
    confidence_lift: str = "probable->confirmed"


def frida_script_for(finding_class: str, pkg: str = "", fn: str = "") -> str:
    """按漏洞类别返回 frida JS 模板（替换占位符），找不到返回空串。"""
    if finding_class in _CRYPTO_KEYS:
        tpl = _FRIDA_TEMPLATES["crypto-key-extract"]
    elif finding_class in _AUTH_KEYS:
        tpl = _FRIDA_TEMPLATES["runtime-cred"]
    elif finding_class == "ssl-unpinning" or finding_class == "weak-cert-validation":
        tpl = _FRIDA_TEMPLATES["ssl-unpinning"]
    elif finding_class == "class-dump" or finding_class == "exported-component":
        tpl = _FRIDA_TEMPLATES["class-dump"]
    else:
        return ""
    return tpl.replace("{PKG}", pkg or "com.example").replace("{FN}", fn or "target")


def build_dynamic_plan(static_findings: list, pkg: str = "") -> list[DynamicPlanItem]:
    """把静态 Finding 列表转化为动态验证计划（有优先级，去重同名脚本）。

    除逐 finding 的 frida/adb 步骤外，额外补充两条「跨 finding 的实战引导」：
      - UI 驱动造数据：存储/备份/导出类漏洞需要真实数据产物才能验证，
        用 uiautomator dump + input tap 走应用内流程（隐私弹窗/备份向导）。
      - 离线解密验证：加密密钥类漏洞要证明「密文+密钥材料可离线还原」，
        拉取密文与密钥库，本地复现派生链解密，用结构特征作为证据。
    """
    plan: list[DynamicPlanItem] = []
    seen_script = set()
    classes = {((f.vuln_class or "").lower()) for f in (static_findings or [])}
    for f in static_findings or []:
        cls = (f.vuln_class or "").lower()
        loc = f.location or ""
        if cls == "exported-component":
            plan.append(DynamicPlanItem(
                target=loc, rationale="导出组件越权/未授权调起需运行时确认",
                command=f"adb shell am start -n {pkg}/{loc} --es probe 1",
                evidence_expected="Starting: Intent", oracle_keys=["exported-component"],
            ))
            continue
        script = frida_script_for(cls, pkg, loc)
        if not script:
            continue
        if script in seen_script:
            continue
        seen_script.add(script)
        if cls in _CRYPTO_KEYS:
            ev, ok = "KEY_HEX=", ["crypto-key-extract", "weak-crypto", "signature-key-leak"]
        elif cls in _AUTH_KEYS:
            ev, ok = "[AUTH]", ["runtime-cred", "hardcoded-secret"]
        elif cls in ("ssl-unpinning", "weak-cert-validation"):
            ev, ok = "VERIFY_BYPASSED", ["ssl-unpinning", "weak-cert-validation"]
        else:
            ev, ok = "[CLASS]", ["class-dump"]
        plan.append(DynamicPlanItem(
            target=cls, rationale=f"静态发现 {cls}@{loc} 需运行时证据升级",
            command=f"frida -U -f {pkg or 'com.example'} -l {cls}_hook.js --no-pause",
            evidence_expected=ev, oracle_keys=ok, script=script,
        ))

    # ── 跨 finding 引导：UI 驱动造数据 ──
    if classes & {"insecure-storage", "exported-component", "allow-backup"}:
        plan.append(DynamicPlanItem(
            target="ui-drive-data",
            rationale="存储/备份/导出类漏洞需要真实数据产物才能验证影响。用 uiautomator "
                      "dump + input tap 走应用内流程（隐私弹窗→备份向导→选择数据→开始），"
                      "产生真实密文/产物后再外带分析，比空谈 manifest 权限有力得多。",
            command=(f"adb shell uiautomator dump /sdcard/ui.xml && "
                     f"adb shell cat /sdcard/ui.xml | grep -o 'text=\"[^\"]*\"'  # 读可点文本\n"
                     f"adb shell input tap <x> <y>   # 按目标 bounds 中心点击，逐步导航触发备份/导出"),
            evidence_expected="备份成功/产物文件落盘", oracle_keys=["insecure-storage"],
        ))

    # ── 跨 finding 引导：离线解密验证 ──
    if classes & {"weak-crypto", "hardcoded-secret", "crypto-key-extract", "signature-key-leak"}:
        plan.append(DynamicPlanItem(
            target="offline-decrypt",
            rationale="加密密钥类漏洞的终点危害是「密文+密钥材料可离线还原明文」。别只看"
                      "硬编码常量或弱模式本身，要顺 doEncrypt 实际调用链逆到密钥派生根："
                      "密钥材料是否随包分发（assets/硬编码索引）？随机种子/IV 是否明文写 DB "
                      "且与密文同目录？逐层验证并复现派生链，用解密出的结构特征作证据。",
            command=(f"adb shell find /sdcard -name '*.copyOut' -o -name 'backup_config*.db'  # 定位密文+密钥库\n"
                     f"adb pull <remote_cipher> <local>  # 拉取密文\n"
                     f"python offline_decrypt.py --assets <apk_assets> --db <backup_config.db> --cipher <file>"),
            evidence_expected="BEGIN:VCARD / BEGIN:VMSG / <?xml", oracle_keys=["crypto-key-extract"],
        ))

    return plan


def render_plan(plan: list, env: DynEnv) -> str:
    """把计划渲染成给 agent 的可执行文本（含环境结论 + 每步命令/脚本路径）。"""
    if not plan:
        return "（无可动态验证的静态发现）"
    lines = [f"◆ 动态环境: {env.detail}", ""]
    for i, it in enumerate(plan, 1):
        lines.append(f"[步骤 {i}] 验证 {it.target}")
        lines.append(f"  理由: {it.rationale}")
        if it.script:
            script_rel = f"tools/mobile/frida_hooks/{it.target}_hook.js"
            lines.append(f"  脚本落盘: {script_rel}")
            lines.append(f"  命令: {it.command}  （可替换为 frida -U -f <pkg> -l {script_rel}）")
        else:
            lines.append(f"  命令: {it.command}")
        lines.append(f"  期望证据(照抄到 finding.evidence): {it.evidence_expected}")
        lines.append("")
    return "\n".join(lines)


def write_hooks(plan: list, hook_dir) -> list[str]:
    """把计划里的 frida 脚本落盘，返回写出的文件路径列表。"""
    import os
    os.makedirs(hook_dir, exist_ok=True)
    written = []
    for it in plan:
        if not it.script:
            continue
        p = os.path.join(hook_dir, f"{it.target}_hook.js")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(it.script)
        written.append(p)
    return written