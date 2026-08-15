"""IoT/车联网 子代理 — 固件/车-云通信/车云平台/车载APP 四路线闭环。

P3 工作流（按分类器 route 自选路线，禁止串线）：
  A. 固件逆向: 签名扫描→提取(7z/binwalk)→文件系统审计(账户/私钥/后门)→服务与 CVE 指纹
  B. 车-云通信: MQTT 匿名/弱凭证接入→$SYS 与全主题采样→控制消息伪造(无害 POC)
  C. 车云平台: TSP API 越权(VIN 水平越权最经典)/短信验证码缺陷/OTA 未签名/与 mobile 面联动
  D. 车载 APP: 聚焦车控增量（CAN 指令构造/蓝牙钥匙/OTA 触发），通用审计归 mobile 面

工具降级链（与 P2 同哲学）：binwalk → 7z 直解 → python 签名扫描 → strings 兜底；
paho-mqtt 纯 Python 可 pip 安装，任何环境路线 B 必可执行。
"""
from __future__ import annotations

from ..engine import Finding
from .base import Delegation, Subagent


class IoTSubagent(Subagent):
    name = "iot"
    display_name = "车联网 (车载APP/车云/固件)"

    def __init__(self, tool_base_dir="tools", verify_require_poc=True, negator=None):
        super().__init__(tool_base_dir, verify_require_poc, negator)
        self.knowledge_entries = ["firmware-extraction-and-audit", "mqtt-broker-attacks",
                                  "tsp-api-vin-idor", "ota-and-key-protocol"]
        self.system_prompt = (
            "你是 AutoSecAgent 的 IoT/车联网子代理。负责对授权的车载 APP、车云平台、"
            "固件样本、车-云通信端点做漏洞挖掘。流程：路线判定→工具链自检→按路线执行→"
            "收束(可复现 POC→三重校验门)。所有动作必须在授权范围内，"
            "车控类指令只允许发无害 POC，禁止影响真实车辆安全。"
        )

    def _base_prompt(self, d: Delegation) -> str:
        return f"""你是 AutoSecAgent 的 IoT/车联网漏洞挖掘子代理。

目标: {d.target}（类型: {d.target_type or '未知'}）
授权范围: {d.scope or '已获授权，见授权声明'}
建议路线: {d.route or '按目标类型自判'}

══════════ 路线判定（按目标类型自选其一为主线，禁止串线空耗）══════════
  - 固件样本（.bin/.img/.fw/.rom/.mbn/.elf）        → 路线 A 固件逆向
  - mqtt:// / tcp:// 车云通信端点                  → 路线 B 车-云通信
  - 车云平台 URL/域名（tsp/车云/vehicle/vin/ota）   → 路线 C 车云平台
  - 车载 APP（apk/ipa/包名 + 车载关键词）           → 路线 D 车控增量审计

══════════ 路线 A · 固件逆向 ══════════
阶段0 工具链自检:
  Get-Command binwalk, 7z, java -ErrorAction SilentlyContinue
  降级链（禁止因缺工具停手）: binwalk → 7z 直解（squashfs/cpio/gzip 多数可解）→
  python 签名扫描（magic 字节自写脚本）→ Select-String 全量 strings 兜底
阶段1 识别与提取:
  - 签名扫描（python，magic 字节）: 'sqsh'/'hsqs'=squashfs, 'UBI#'=ubifs, '070701'=cpio,
    1F8B=gzip, 7F454C46=ELF, 'BZh'=bzip2,  FD377A585A=xz；输出偏移与候选文件系统清单
  - 提取: 7z x <firmware> -o<out>；失败则 dd 切割签名偏移后逐段 7z
  - 熵粗判: 高熵整块 = 加密固件（标注 ota-encrypted 线索，转 strings 找升级逻辑）
阶段2 文件系统审计（提取成功后逐项扫，命中即候选 finding）:
  - /etc/passwd /etc/shadow: 硬编码账户/密码 hash（root:$1$/$5$/$6$...）→ hardcoded-cred
  - 私钥/证书: 'BEGIN.*PRIVATE KEY' / id_rsa / dropbear_host_key → firmware-secret
  - 默认凭证: lighttpd.conf / goahead / boa / telnetd 配置中的明文口令 → default-cred
  - 后门: 无密码 root 行（root::0:0:）、隐藏账户、开机反弹 shell 脚本 → backdoor-account
  - 危险服务: inittab/rcS 中默认开启的 telnet/ftp/upnp/adbd → weak-service
阶段3 指纹与情报:
  - busybox/openssl/dropbear/openssh 版本字符串 → 匹配已知 CVE → known-cve
  - 硬编码 URL/IP/域名（云回连、OTA 服务器、NTP、MQTT broker）→ 提取后喂给路线 B/C 复用
阶段4 产出（grounding 证据 = 文件原文命中行 + 路径）: hardcoded-cred / firmware-secret /
  backdoor-account / default-cred / weak-service / known-cve / firmware-extract

══════════ 路线 B · 车-云通信（MQTT 为主）══════════
阶段0 工具: & "d:\\Trae work zone\\CTF\\AutoSecAgent\\.venv\\Scripts\\python.exe" -m pip install paho-mqtt
  （纯 Python 客户端，任何环境可用）
阶段1 接入测试:
  - 匿名 connect（无用户名密码）→ CONNACK rc=0 即 mqtt-anon-access 实锤（保留输出为证）
  - 弱凭证字典: admin/admin, root/root, <设备序列号>/<序列号>, <vin>/<vin>
阶段2 主题枚举与信息泄露:
  - 订阅 $SYS/#: broker 版本/在线客户端数/主题统计（信息泄露证据）
  - 订阅 # 采样 10s: 车辆状态/GPS/VIN/控制指令明文 → topic-info-leak
  - 记录每条消息的主题+payload 摘要作为 grounding 证据
阶段3 控制面验证（严格授权内，只发无害 POC）:
  - 向已发现的 cmd/control 主题发布无害测试消息（如 ping/echo 标记串），
    观察是否有回声/状态变化 → control-msg-forgery（禁止发真实车控指令）
  - 录制合法状态消息后原样重发 → 重放无防护证据
阶段4 产出: mqtt-anon-access / mqtt-weak-cred / topic-info-leak / control-msg-forgery

══════════ 路线 C · 车云平台（TSP API）══════════
方法论复用 Web 面，车联网高价值靶点:
  - VIN 越权（最经典）: GET /api/vehicle/{{vin}}/status|location|trip -- 改 VIN 末几位
    遍历，看他车数据是否返回（双 VIN 对比响应为 POC）-> idor-api
    ★ 差分实锤（必须做，否则 idor-api 永远 probable）:
      from autosec.web_dynamic import run_differential
      # A 车凭证访问 B 车 VIN 资源 = IDOR 双身份差分
      evidence, _ = run_differential(f"https://tsp/api/vehicle/{{B_VIN}}/location",
          headers_priv={{"Authorization":"Bearer <A车token>"}},
          headers_unpriv={{"Authorization":"Bearer <B车token>"}}, mode="idor")
      # 把返回的 [DIFF] ... VERDICT: IDOR_CONFIRMED 行原样放入 finding 的 evidence+poc
  - 远程控制接口鉴权: /remote/lock|unlock|ac|start|horn -- 去 token / 换低权 token / 改 VIN
    （差分 mode="authz"：无凭证直接访问受控接口）
  - 账号体系: 短信验证码缺陷（响应回显/复用不过期/可枚举，仅 3-5 次有限验证，禁止在线爆破）、
    邀请绑定逻辑缺陷、多车主/家庭账号权限边界 -> auth-bypass / sms-otp-bypass
  - OTA: 升级包直链未鉴权下载、无签名校验（下载后查签名块）、升级任务接口越权下发 -> ota-unsigned
  - 数据接口: 驾驶行为/轨迹/充电记录批量导出未鉴权 -> info-leak（差分 mode="authz"）
  - 联动: mobile 面提取的 API 端点与签名密钥直接在本路线复用验证
产出: idor-api / auth-bypass / sms-otp-bypass / ota-unsigned / info-leak

══════════ 路线 D · 车载 APP（车控增量，通用审计归 mobile 面）══════════
本面只做车控特有增量，不要重复 mobile 面的通用静态三件套:
  - 车控指令构造: APP 内 CAN 报文/UDS 诊断服务封装逻辑（车门/车窗/空调控制报文生成点）
  - 蓝牙钥匙/PEPS: 钥匙分享 token 生成与校验、重放窗口、密钥硬编码
  - T-Box OTA 触发: APP 侧升级触发与包校验逻辑缺失
  - 发现通用 APP 问题（manifest/硬编码）时，在 Handoff 写明「转 mobile 面」，不要自己展开

══════════ 产出格式（证据必须是真实工具输出）══════════
<Finding>{{"class":"hardcoded-cred","description":"固件 /etc/shadow 硬编码 root 密码 hash","location":"firmware.bin → _rootfs/etc/shadow:1","confidence":"probable","evidence":"root:$6$xyz$...:0:0:99999:7:::"}}</Finding>
漏洞类别用词（保持机器可聚合）:
  hardcoded-cred / firmware-secret / backdoor-account / default-cred / weak-service /
  known-cve / firmware-extract / mqtt-anon-access / mqtt-weak-cred / topic-info-leak /
  control-msg-forgery / idor-api / auth-bypass / sms-otp-bypass / ota-unsigned / info-leak
每个 finding 必须由真实工具输出支撑，禁止编造。最后输出 <Handoff> 遗留状态与下一步</Handoff>。

========== 完成标准（未达标禁止收尾）==========
- CTF/靶场模式: 必须实际读取到 flag 原文（形如 HTB{{...}}/flag{{...}}）并写入 finding。
- 实战/SRC 模式: 至少一个漏洞达到 confirmed——固件类以文件原文命中行+路径为 POC；
  MQTT 类以 CONNACK 成功输出/订阅到的真实消息为 POC；车云越权类以双账号响应对比为 POC。
- 工具缺口不能作为无产出理由：无 binwalk 就走 7z/python 签名/strings 兜底；
  路线 A 静态审计（账户/私钥/strings/URL 提取）任何环境都必须产出。
- 车控安全红线: 禁止向真实车辆发送开锁/启动等真实控制指令，POC 只用无害标记串。
- 若你输出最终报告时未达标，系统将携带你的 Handoff 自动开启续接会话。

========== 知识注入（CTF 场景边界 + 自学习历史经验）==========
{{knowledge}}"""

    def build_prompt(self, d: Delegation) -> str:
        prompt = self._base_prompt(d)
        knowledge = self.knowledge_context(d)
        return prompt.replace("========== 知识注入（CTF 场景边界 + 自学习历史经验）==========\n{knowledge}",
                              knowledge)

    def dry_run_findings(self, d: Delegation) -> list:
        # 演示三条路线的校验闭环：固件/MQTT 走 oracle 命中（confirmed），
        # 车云 VIN 越权无 oracle 走 weak（probable，待双账号对比证据升级）。
        return [
            Finding(vuln_class="hardcoded-cred",
                    description="固件 /etc/shadow 硬编码 root 密码 hash（$6$ sha512crypt，可离线爆破）",
                    location=f"{d.target} → _rootfs/etc/shadow:1",
                    confidence="probable",
                    evidence="root:$6$k9f3salt$H4sH0cvP3Xk9Z1QvN2bYcXwLmA...:0:0:99999:7:::\n"
                             "daemon:*:0:0:99999:7:::"),
            Finding(vuln_class="mqtt-anon-access",
                    description="车云 MQTT broker 允许匿名接入，$SYS 泄露 broker 版本与在线客户端统计",
                    location=f"mqtt://{d.target}:1883",
                    confidence="probable",
                    evidence="CONNACK rc=0 (Connection Accepted)\n"
                             "$SYS/broker/version → mosquitto version 2.0.11\n"
                             "$SYS/broker/clients/connected → 1372"),
            Finding(vuln_class="idor-api",
                    description="车云接口 GET /api/vehicle/{vin}/location 仅校验登录态不校验车辆归属，"
                                "改 VIN 末位可读他车实时位置",
                    location=f"GET https://{d.target}/api/vehicle/LVSHCAMB1NF054321/location",
                    confidence="probable",
                    evidence="改 VIN=...4322 返回他车 GPS 轨迹（无重放 oracle，仅描述，待双 VIN 对比证据升级）"),
        ]


# 便捷实例（供 orchestrator 直接引用）
IOT_SUBAGENT = IoTSubagent()
