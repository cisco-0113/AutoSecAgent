"""授权声明校验冒烟测试 — 目标范围精确匹配。

覆盖 covers() 的四种匹配语义：
  1. 通配符域名 *.oppo.com -> 后缀匹配（含根域），防 evil-oppo.com 误匹配
  2. 包名段级精确匹配：段前缀 / 段通配 / 完整段边界（防子串误匹配）
  3. APK 路径嵌包名提取匹配
  4. 强 TLD 域名（com.example.com）不落入包名规则

运行: python smoke_test_authorization.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.authorization import Authorization, load_authorization

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def covers(targets, target):
    return Authorization(authorized=True, targets=targets).covers(target)


print("\n[1] 通配符域名匹配")
check("*.oppo.com 命中子域 api.oppo.com", covers(["*.oppo.com"], "api.oppo.com"))
check("*.oppo.com 命中根域 oppo.com", covers(["*.oppo.com"], "oppo.com"))
check("*.oppo.com 不命中 evil-oppo.com", not covers(["*.oppo.com"], "evil-oppo.com"))

print("\n[2] 包名段级精确匹配")
check("完整包名精确命中", covers(["com.oppo.usercenter"], "com.oppo.usercenter"))
check("不误匹配后缀追加（usercenter vs usercenter2）",
      not covers(["com.oppo.usercenter"], "com.oppo.usercenter2"))
check("段前缀规则命中子包（com.oppo -> com.oppo.usercenter）",
      covers(["com.oppo"], "com.oppo.usercenter"))
check("段前缀规则不误匹配不同段（com.oppo vs com.oppo2.usercenter）",
      not covers(["com.oppo"], "com.oppo2.usercenter"))
check("段通配命中（com.oppo.* -> com.oppo.usercenter）",
      covers(["com.oppo.*"], "com.oppo.usercenter"))
check("段通配不跨段（com.oppo.* vs com.oppo.a.b）",
      not covers(["com.oppo.*"], "com.oppo.a.b"))

print("\n[3] APK 路径嵌包名")
check("路径内包名提取匹配",
      covers(["com.coloros.backuprestore"],
             r"D:\x\com.coloros.backuprestore.apk"))

print("\n[4] 强 TLD 域名不落入包名规则")
check("com.example.com 仍按域名精确匹配",
      covers(["com.example.com"], "com.example.com"))
check("com.example.com 不误配 com.example.com2",
      not covers(["com.example.com"], "com.example.com2"))

print("\n[5] 未限制清单全授")
check("空清单视为全授", covers([], "anything.example.com"))

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)
