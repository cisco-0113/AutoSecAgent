"""攻击面分类器。

根据输入目标（域名/URL/APK/IPA/固件/车云地址等）识别其所属攻击面：
  - web    : 域名、URL、IP、端口、API 网关
  - mobile : APK、IPA、Android/iOS 包
  - iot    : 固件(bin/img)、车云地址、MQTT/T-Box、车载 APP

分类器是 P0 验收的核心：CLI 能启动并正确识别攻击面。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---- 目标类型常量 ----
T_URL = "url"
T_DOMAIN = "domain"
T_IP = "ip"
T_APK = "apk"
T_IPA = "ipa"
T_FIRMWARE = "firmware"
T_MQTT = "mqtt"
T_APP = "app"          # 泛化车载/移动 APP 包名
T_UNKNOWN = "unknown"


@dataclass
class Classification:
    """分类结果。"""

    raw: str                       # 原始输入
    target_type: str = T_UNKNOWN   # 目标类型
    attack_surfaces: list[str] = field(default_factory=list)  # 命中的攻击面
    route: str = ""                # 建议路线（IoV 内部细分）
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def primary(self) -> str:
        return self.attack_surfaces[0] if self.attack_surfaces else T_UNKNOWN


# ---- 指纹规则 ----

_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?$")
_URL_RE = re.compile(r"^(?:https?|ws|wss|mqtt)://", re.I)
_APK_RE = re.compile(r"\.apk$", re.I)
_IPA_RE = re.compile(r"\.ipa$", re.I)
_FW_RE = re.compile(r"\.(bin|img|rom|fw|mbn|elf)$", re.I)
_MQTT_RE = re.compile(r"^(?:mqtt|tcp)://", re.I)

# 车载/车云关键词：命中即偏向 IoV
_IOV_WORDS = ("tbox", "t-box", "telematics", "vin", "ota", "vehicle", "car",
              "车云", "车载", "车机", "tsp", "obd", "ecu", "ivi", "车联网")
# 移动端包名关键词
_MOBILE_PACKAGE_RE = re.compile(r"^(com|org|cn|io|net)\.[a-z0-9_.]{2,}$", re.I)
# 传统强 TLD：包名几乎不以这些结尾；末段命中则按域名处理（如 api.example.com）
_STRONG_TLD = {"com", "net", "org", "cn", "edu", "gov", "mil", "int"}


def _looks_like_package(t: str) -> bool:
    """区分包名与域名（二者同构：com.example.banking vs api.example.com）。

    规则：以 com/org/cn/io/net 开头且段数 ≥ 3 且末段不是传统强 TLD → 包名。
    com.example.app / com.tbox.vehicle.app 这类「现代 TLD 结尾」在真实世界 99% 是包名。
    """
    if not _MOBILE_PACKAGE_RE.match(t):
        return False
    segs = t.split(".")
    if len(segs) < 3:
        return False
    return segs[-1].lower() not in _STRONG_TLD


def _hit_iov(text: str) -> bool:
    low = text.lower()
    return any(w in low for w in _IOV_WORDS)


def classify(target: str) -> Classification:
    """对单个目标做攻击面分类。"""
    t = target.strip()
    res = Classification(raw=t)
    low = t.lower()

    # 1) MQTT / 车云协议端点
    if _MQTT_RE.match(low) or low.startswith("tcp://") and _hit_iov(t):
        res.target_type = T_MQTT
        res.attack_surfaces = ["iot"]
        res.route = "车-云通信"
        res.confidence = 0.95
        res.reasons.append("识别为 MQTT/车云通信端点")
        return res

    # 2) 固件
    if _FW_RE.search(low):
        res.target_type = T_FIRMWARE
        res.attack_surfaces = ["iot"]
        res.route = "固件逆向"
        res.confidence = 0.95
        res.reasons.append("识别为固件样本")
        return res

    # 3) APK
    if _APK_RE.search(low):
        res.target_type = T_APK
        res.attack_surfaces = ["mobile"]
        if _hit_iov(t):
            res.attack_surfaces = ["iot", "mobile"]
            res.route = "车载 APP 逆向"
            res.confidence = 0.9
            res.reasons.append("识别为车载 APP (APK)")
        else:
            res.attack_surfaces = ["mobile"]
            res.confidence = 0.95
            res.reasons.append("识别为移动端 APK")
        return res

    # 4) IPA
    if _IPA_RE.search(low):
        res.target_type = T_IPA
        res.attack_surfaces = ["mobile"]
        res.confidence = 0.95
        res.reasons.append("识别为移动端 IPA")
        return res

    # 5) URL / 域名 / IP（先判包名歧义：com.example.banking 这类三段式非 TLD 结尾是包名）
    if _looks_like_package(t):
        res.target_type = T_APP
        if _hit_iov(t):
            res.route = "车载 APP 逆向"
            res.attack_surfaces = ["iot", "mobile"]
            res.confidence = 0.85
            res.reasons.append("识别为车载 APP 包名")
        else:
            res.attack_surfaces = ["mobile"]
            res.confidence = 0.8
            res.reasons.append("识别为移动端包名（非 TLD 结尾的三段式）")
        return res
    if _URL_RE.match(low):
        res.target_type = T_URL
        res.attack_surfaces = ["web"]
        if _hit_iov(t):
            res.route = "车云平台接口"
            res.attack_surfaces = ["iot", "web"]
            res.confidence = 0.85
            res.reasons.append("识别为车云平台 URL")
        else:
            res.attack_surfaces = ["web"]
            res.confidence = 0.9
            res.reasons.append("识别为 URL")
        return res
    if _IPV4_RE.match(t):
        res.target_type = T_IP
        res.attack_surfaces = ["web"]
        res.confidence = 0.85
        res.reasons.append("识别为 IP 地址")
        return res
    if _DOMAIN_RE.match(t):
        res.target_type = T_DOMAIN
        res.attack_surfaces = ["web"]
        if _hit_iov(t):
            res.route = "车云平台"
            res.attack_surfaces = ["iot", "web"]
            res.confidence = 0.8
            res.reasons.append("识别为车云相关域名")
        else:
            res.confidence = 0.9
            res.reasons.append("识别为域名")
        return res

    # 6) 移动端包名 (com.xxx)
    if _MOBILE_PACKAGE_RE.match(t):
        res.target_type = T_APP
        res.attack_surfaces = ["mobile"]
        if _hit_iov(t):
            res.route = "车载 APP 逆向"
            res.attack_surfaces = ["iot", "mobile"]
            res.confidence = 0.85
            res.reasons.append("识别为车载 APP 包名")
        else:
            res.confidence = 0.8
            res.reasons.append("识别为移动端包名")
        return res

    # 7) 未知
    res.target_type = T_UNKNOWN
    res.attack_surfaces = []
    res.confidence = 0.0
    res.reasons.append("无法自动识别目标类型，需人工指定 --surface")
    return res


def display(clf: Classification) -> str:
    """分类结果的终端展示。"""
    lines = [
        f"目标       : {clf.raw}",
        f"目标类型   : {clf.target_type}",
        f"攻击面     : {', '.join(clf.attack_surfaces) if clf.attack_surfaces else '未知'}",
    ]
    if clf.route:
        lines.append(f"建议路线   : {clf.route}")
    lines.append(f"置信度     : {clf.confidence:.0%}")
    lines.append(f"依据       : {'; '.join(clf.reasons)}")
    return "\n".join(lines)