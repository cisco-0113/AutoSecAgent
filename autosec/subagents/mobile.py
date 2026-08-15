"""Mobile 子代理 — 拆包→敏感信息→越权接口验证 的移动端闭环。

P2 工作流（静态为主，动态增强）：
  0. 工具链自检: jadx/apktool 需 java；无 java 时降级为 androguard（纯 Python pip 包），
     再无则 zip 解包 + strings 兜底；frida/adb 缺失时跳过动态阶段并在报告标注缺口
  1. 拆包: apktool d（smali+明文 manifest）/ jadx（java 伪码）/ androguard（manifest+dex 解析）
  2. 敏感信息: manifest 攻击面（debuggable/allowBackup/exported 组件）、硬编码密钥与内网地址、
     明文流量与证书校验配置、WebView/深链注入面
  3. 越权接口验证: 从代码提取 API 端点与鉴权方式 → 重放/篡改参数验证水平垂直越权 →
     签名算法本地还原后合法调用
  4. 动态（可选）: frida hook SSL pinning/加密函数，adb am 调起导出组件
  5. 产出: Finding 过三重校验门（静态类漏洞以 manifest/代码原文为 grounding 证据）
"""
from __future__ import annotations

from ..engine import Finding
from .base import Delegation, Subagent


class MobileSubagent(Subagent):
    name = "mobile"
    display_name = "移动端 APP (Android/iOS)"

    def __init__(self, tool_base_dir="tools", verify_require_poc=True, negator=None):
        super().__init__(tool_base_dir, verify_require_poc, negator)
        self.knowledge_entries = ["apk-static-triage", "frida-dynamic-instrumentation",
                                  "api-privilege-escalation", "hardcoded-secret-patterns"]
        self.system_prompt = (
            "你是 AutoSecAgent 的 Mobile 子代理。负责对授权的 Android/iOS 应用做"
            "静态拆包审计与动态插桩验证。流程：工具链自检→拆包→敏感信息扫描→"
            "越权接口验证→(可选)frida 动态分析→组合链构造→收束(可复现 POC→三重校验门)。"
            "发现多个低危/中危 finding 时，优先尝试把它们串成攻击链达成更高攻击目的"
            "（数据流+密钥流+触达面三线追踪），而非各自独立提交。所有动作必须在授权范围内。"
        )

    def _base_prompt(self, d: Delegation) -> str:
        return f"""你是 AutoSecAgent 的 Mobile 漏洞挖掘子代理。

目标: {d.target}
授权范围: {d.scope or '已获授权，见授权声明'}
建议路线: {d.route or '通用移动端审计'}

══════════ 阶段 0 · 工具链自检（必做，决定后续路径）══════════
先探测工具链可用性（优先 PATH，其次项目内 tools/ 目录）：
  python  = <python 解释器>（推荐装 androguard / frida / capstone / pyelftools）
  adb     = <项目>/tools/mobile/bin/platform-tools/adb 或 PATH 中的 adb
  java    = <java>（apktool/jadx 需要，openjdk 17+）
  apktool = java -jar <项目>/tools/mobile/bin/apktool.jar
  frida   = <frida>（动态 hook，缺失则跳过阶段 4 并标注缺口）
可用 autosec/mobile_dynamic.py 的 probe_environment() 一键探测：
  python -c "from autosec.mobile_dynamic import probe_environment; print(probe_environment())"
若 target 是包名（非 APK 文件）：先用 adb 提取 APK 再分析：
  adb shell pm path <pkg>                     # 得到 base.apk 路径
  adb pull /data/app/.../base.apk <workdir>\<pkg>.apk
降级链（逐级兜底，禁止因缺工具而停手）：
  apktool（需 java）→ androguard（纯 Python）→ Expand-Archive 解 zip + Select-String 扫 strings
frida/adb 缺失 → 跳过阶段 4 动态分析，在报告中明确标注「动态验证缺口」。

══════════ 阶段 1 · 拆包（APK 为主，IPA 同理解 zip）══════════
  # 首选（有 java）:
  apktool d -f -o <workdir>\\apk_out <target>          # smali + 明文 AndroidManifest + 资源
  jadx -d <workdir>\\jadx_out <target>                 # java 伪码，便于读逻辑
  # 兜底（无 java，用 androguard 脚本）:
  python -c "from androguard.core.apk import APK; a=APK(r'<target>'); print(a.get_package()); print(a.get_android_manifest_xml().toprettyxml())"
  python -c "from androguard.misc import AnalyzeAPK; a,d,dx=AnalyzeAPK(r'<target>'); [print(s) for s in dx.get_strings()]"
  # IPA: Expand-Archive <target> <workdir>\\ipa_out → Payload\\*.app\\Info.plist（python plistlib 解析）

══════════ 阶段 2 · 敏感信息扫描（静态，每个命中都是候选 finding）══════════
  a) Manifest 攻击面（AndroidManifest.xml 原文为 grounding 证据）:
     - android:debuggable="true" → debuggable（生产包可调试 = 高危）
     - android:allowBackup="true" → backup 数据可抽取
     - exported="true" 且无 android:permission 的 activity/service/receiver/provider → 组件暴露
  b) 硬编码秘密（正则扫 smali/resources/assets/res/raw/strings.xml）:
     API key / token / secret / password / BEGIN.*PRIVATE KEY / AKIA[0-9A-Z]{{16}} /
     内网 IP 与测试域名 / 硬编码加密密钥（AES/DES key 常量）
  c) 网络安全配置:
     - usesCleartextTraffic="true" 或 networkSecurityConfig 中 cleartextTrafficPermitted="true"
     - trust-anchors 包含 user 证书（可被用户证书 MITM）
     - 无任何 CertificatePinner / TrustManager 自定义 → 抓包无门槛
  d) WebView / 深链:
     - setJavaScriptEnabled(true) + addJavascriptInterface + loadUrl 参数可控（api<17 = RCE）
     - intent-filter data scheme/host 未校验 → 深链注入（钓鱼/越权跳转/参数注入）
  e) 存储: SharedPreferences/SQLite 明文存 token/密码；外部存储 (getExternalStorage) 写敏感文件

══════════ 阶段 3 · 越权接口验证（核心：从 APP 到后端 API 的越权链）══════════
  a) 端点提取: 从 smali/jadx 找 Retrofit 注解 (@GET/@POST)、OkHttp url(...) 、
     HttpURLConnection、字符串中的 https?:// API 地址，汇总接口清单（路径+参数+鉴权头）
  b) 鉴权机制识别: Authorization header / 自定义 sign 参数 / token 在 SharedPreferences
  c) 越权验证（对授权后端真实发请求，带证据）:
     - 水平越权: 改 uid/orderId/deviceId 等 ID 参数，看他账号数据是否返回
     - 垂直越权: 去掉/替换低权 token 调管理端接口
     - 参数篡改: 金额/积分/状态字段篡改（业务逻辑）
  d) 签名还原: 若接口有 sign 参数，从代码定位生成逻辑（常见 HMAC-SHA256(参数拼接+salt)），
     本地用 python 复现签名后合法调用——这本身是「签名密钥硬编码」的证据

══════════ 阶段 4 · 动态分析（静态→运行时证据升级，优先用动态工作流模块）══════════
用 autosec/mobile_dynamic.py 把阶段 2/3 的静态发现转成可执行动态验证：
  # 1) 探测环境（frida/adb/设备），写进报告：
  python -c "from autosec.mobile_dynamic import probe_environment; print(probe_environment())"
  # 2) 由静态 Finding 生成动态验证计划 + 落盘 frida 脚本：
  build_dynamic_plan(findings, pkg) → render_plan(...) / write_hooks(plan, <workdir>)
  # 3) 有设备时实跑并收集证据（frida 输出/组件调起日志），无设备时输出计划+手工步骤：
  frida -U -f <package> -l <workdir>\<cls>_hook.js --no-pause   # hook SSL/crypto/登录令牌
  adb shell am start -n <pkg>/.<ExportedActivity> --es/--ei 注入 extra   # 组件暴露实锤
  adb shell run-as <pkg> / am broadcast      # debuggable/接收器滥用实锤
动态证据标识（命中即把对应静态 probable 升级为 confirmed，evidence 照抄）：
  [CRYPTO] KEY_HEX=/IV_HEX=  → crypto-key-extract / weak-crypto / signature-key-leak
  [AUTH] SP_PUT/HEADER token → runtime-cred / hardcoded-secret
  VERIFY_BYPASSED           → ssl-unpinning / weak-cert-validation
  Starting: Intent          → exported-component 实锤
若 frida/adb 均不可用或无可连设备：不要简单标「缺口」了事，必须用 build_dynamic_plan
产出可执行验证计划（命令+脚本路径+预期证据），并明确标注「待设备接入后实跑」。

══════════ 阶段 4.5 · 组合链构造（多个低危发现 → 一条高危害攻击链）══════════
关键经验：单个「导出组件 / 弱加密 / 硬编码密钥 / 不安全存储 / 明文流量」独立提交往往
被 SRC 按无危或低危处理（尤其导出组件、纯反编译报告常被点名不收）。真正有价值的是
把它们串成「攻击者可端到端执行」的链，按链的终点危害定级，而非各环节单独定级。
按三线追踪逐环验证，每环都必须有真实工具输出，禁止臆断：
  1) 数据流：敏感数据（短信/通讯录/通话记录/凭据/token）从哪产生 → 经过哪些组件处理 →
     如何加密 → 落盘到哪个文件/目录/DB → 是否可被攻击者触达（共享存储？导出组件？）。
  2) 密钥流：加密 key 从哪派生——硬编码常量 / assets 随包文件 / 随机值+明文写 DB /
     Android Keystore / 服务端下发？派生材料（salt/索引数组/随机种子）是否随包分发或
     与密文同目录共存？逐层逆到根，凡「离线可恢复」即可作为链的核心一环。
  3) 触达面：攻击者如何无交互/弱交互拿到密文与密钥材料——导出组件（am startservice /
     broadcast 实锤）、MANAGE_EXTERNAL_STORAGE 类权限、deeplink、备份/迁移流程。
  4) 端到端验证（最关键）：把链写成可执行脚本（如 提取assets→读DB密钥→HMAC派生→
     AES离线解密→还原明文），跑通后以「解密成功还原 BEGIN:VCARD/BEGIN:VMSG/<?xml」
     等结构特征作为 finding 的 evidence（照抄真实输出），敏感原文不落报告。
  5) 命名与提交：组合成一个漏洞（class 取链的使能缺陷，如 crypto-key-extract /
     insecure-storage），命名「类型可提取资产，可终点危害」，风险影响评估
     写链的终点危害（解密出短信/通讯录=移动端中危③）。

══════════ 阶段 5 · 产出（严格格式，证据必须是真实工具输出）══════════
<Finding>{{"class":"hardcoded-secret","description":"...","location":"smali/com/x/Config.smali:42","confidence":"probable","evidence":"const-string v0, \\"AKIA...\\""}}</Finding>
漏洞类别用词（保持机器可聚合）:
  debuggable / allow-backup / exported-component / hardcoded-secret / cleartext-traffic /
  weak-cert-validation / webview-jsi / deeplink-injection / insecure-storage /
  idor-api / signature-key-leak / weak-crypto
每个 finding 必须由真实工具输出支撑，禁止编造。最后输出 <Handoff> 遗留状态与下一步</Handoff>。

========== 完成标准（未达标禁止收尾）==========
- CTF/靶场模式: 必须实际读取到 flag 原文（形如 HTB{{...}}/flag{{...}}）并写入 finding。
  ★ 关键经验：捕获到完整 flag 时，finding 的 class 必须用 "flag"，且 evidence 字段只放
    flag 原文本身（不要放命令/脚本输出）。这样系统会对它做 strong 校验并直接判为
    confirmed。若你把 flag 标成 weak-crypto / hardcoded-secret 等其他类别，即使拿到了
    flag，系统的结构化校验也会判为不达标（confirmed=0），只能靠证据兜底。多个候选时
    只输出验证过唯一性/可打印性成立的那个，并附推导链。
- 实战/SRC 模式: 至少一个漏洞达到 confirmed——静态类漏洞以 manifest/代码原文 + 命中行
  为 POC；接口越权类必须给出真实重放请求与响应差异（两账号对比）为 POC。
- 工具缺口不能作为无产出的理由：无 java 就走 androguard/zip 兜底，无 frida 就跳过动态并标注，
  静态三件套（manifest/硬编码/端点清单）任何环境下都必须产出。
- 若你输出最终报告时未达标，系统将携带你的 Handoff 自动开启续接会话。

========== 知识注入（CTF 场景边界 + 自学习历史经验）==========
{{knowledge}}"""

    def build_prompt(self, d: Delegation) -> str:
        prompt = self._base_prompt(d)
        knowledge = self.knowledge_context(d)
        return prompt.replace("========== 知识注入（CTF 场景边界 + 自学习历史经验）==========\n{knowledge}",
                              knowledge)

    def dry_run_findings(self, d: Delegation) -> list:
        # 演示三类典型移动端漏洞的校验闭环：静态证据走 oracle 命中（confirmed），
        # 接口越权无 oracle 走 weak（probable，待真实重放证据升级）。
        return [
            Finding(vuln_class="debuggable",
                    description="生产 APK 开启 android:debuggable，可 run-as 读取沙盒数据 / jdb 附加调试",
                    location=f"{d.target}: AndroidManifest.xml <application>",
                    confidence="probable",
                    evidence='<application android:debuggable="true" android:allowBackup="true"'),
            Finding(vuln_class="hardcoded-secret",
                    description="硬编码 AES 密钥与内网 API 地址（smali 常量），签名密钥同库泄露",
                    location=f"{d.target}: smali/com/example/net/Config.smali:87",
                    confidence="probable",
                    evidence='const-string v1, "AES/ECB/PKCS5Padding"\nconst-string v2, "k9f3HardC0dedKey!!"\nconst-string v3, "http://10.20.30.40:8080/api/"'),
            Finding(vuln_class="idor-api",
                    description="订单接口 GET /api/order/{id} 仅校验 token 不校验归属，改 id 可读他人订单",
                    location=f"POST {d.target} → /api/order/10086 (from smali/com/example/api/OrderService.smali)",
                    confidence="probable",
                    evidence="改 id=10087 返回他人收货地址（无重放 oracle，仅描述，待双账号对比证据升级）"),
        ]


# 便捷实例（供 orchestrator 直接引用）
MOBILE_SUBAGENT = MobileSubagent()
