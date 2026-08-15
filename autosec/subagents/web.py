"""Web 子代理 — 侦察→挖洞→校验的 Web 闭环。"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..engine import Finding
from .base import Delegation, Subagent


class WebSubagent(Subagent):
    name = "web"
    display_name = "Web / API 资产"

    def __init__(self, tool_base_dir="tools", verify_require_poc=True, negator=None):
        super().__init__(tool_base_dir, verify_require_poc, negator)
        self.knowledge_entries = ["web-attack-methods", "ssrf-to-metadata-and-internal",
                                  "jwt-alg-none-and-weak-secret", "flask-ssti-jinja2"]
        self.system_prompt = (
            "你是 AutoSecAgent 的 Web 子代理。负责对授权 Web/API 资产进行侦察、"
            "漏洞假设、验证与复现。流程：侦察(子域/端口/指纹)→漏洞(注入/越权/逻辑/SSRF)"
            "→收束(可复现 POC→三重校验门)。所有动作必须在授权范围内。"
        )

    def _base_prompt(self, d: Delegation) -> str:
        return f"""你是 AutoSecAgent 的 Web 漏洞挖掘子代理。

目标: {d.target}
授权范围: {d.scope or '已获授权，见授权声明'}
建议路线: {d.route or '通用 Web 侦察'}

任务（严格按序执行）:
1. 侦察: 枚举子域/端口/服务/框架指纹，锁定高价值资产（管理后台/API 网关/接口）。
2. 挖洞: 针对每个接口按类测试注入(SQL/SSTI/命令)、越权(IDOR/水平垂直)、逻辑、SSRF等。
3. 动态验证（关键--逻辑漏洞必须差分实锤）:
   注入/回显类用重放命中 oracle；越权/逻辑类（idor/auth-bypass/priv-escalation）
   必须用双账号差分对比产出标准 [DIFF] 证据，否则永远停在 probable、无法达标收尾。
   工具（autosec/web_dynamic.py，任何环境可用 requests 或 curl）:
     from autosec.web_dynamic import run_differential
     # 双账号 IDOR: 属主凭证 vs 攻击者凭证 访问同一资源 URL
     evidence, results = run_differential(url, headers_priv={{"Cookie":"<属主>"}},
         headers_unpriv={{"Cookie":"<攻击者>"}}, mode="idor")
     # 匿名越权: mode="authz"（无凭证直接访问受保护资源）
     # 垂直越权: mode="priv"（低权角色 vs 管理员）
   evidence 形如:
     [DIFF] GET /api/order/1001 | owner=200(512B) | attacker=200(508B) | body_sim=0.97 | VERDICT: IDOR_CONFIRMED
   把该行原样放入 <Finding> 的 evidence（poc 同放此行），系统校验 [DIFF] 结构 +
   相似度阈值 + VERDICT 标记，三齐即升级 confirmed。VERDICT: NO_DIFF 表示无差异，
   禁止把 NO_DIFF 的差分当漏洞上报。
   双账号准备: 优先注册两个测试账号；只能拿到单账号时用「有效会话 vs 无会话」做
   authz 模式；车云场景可用双 VIN（A 车凭证访问 B 车 VIN）。
4. 利用闭环: 确认漏洞后必须继续推进利用链到最终目标，不得停在"已确认存在"。
5. 产出: 对每个确认漏洞用以下格式输出（必须包含可复现 POC 与真实证据）：

<Finding>{{"class":"sqli","description":"...","location":"POST /api/login","confidence":"probable","evidence":"响应特征"}}</Finding>

每个 finding 必须由真实工具输出支撑，禁止编造。最后输出 <Handoff> 遗留状态与下一步</Handoff>。

========== 完成标准（未达标禁止收尾）==========
- CTF/靶场模式: 必须实际读取到 flag 原文（形如 HTB{{...}}/flag{{...}}）并写入 finding，
  仅确认漏洞存在、仅泄露数据而未提取 flag 一律视为未完成。
- 实战/SRC 模式: 至少一个漏洞达到 confirmed--注入/回显类给完整请求+真实响应；
  越权/逻辑类必须给标准 [DIFF] 差分证据行（见任务3），理论分析、"疑似"、"可能存在"
  不得作为收尾成果。逻辑漏洞不差分=永远 probable=无法收尾，这是硬约束。
- 收尾自检（输出最终报告前逐条确认）:
  (a) 每个 confirmed 是否都有真实工具输出作为证据？
  (b) 利用链是否已走到最终目标（flag/数据/权限），而非中途？
  (c) Handoff 是否写清了未竟事项与下一步具体动作？
- 若你输出最终报告时未达标，系统将携带你的 Handoff 自动开启续接会话，
  要求你从断点继续——所以要么达标，要么把 Handoff 写到能直接续作的程度。
- 路径连续失败 2 次立即切换备选路径，禁止在死胡同上空耗轮次。

========== 知识注入（CTF 场景边界 + 自学习历史经验）==========
{{knowledge}}"""

    def build_prompt(self, d: Delegation) -> str:
        prompt = self._base_prompt(d)
        knowledge = self.knowledge_context(d)
        return prompt.replace("========== 知识注入（CTF 场景边界 + 自学习历史经验）==========\n{knowledge}",
                              knowledge)

    def dry_run_findings(self, d: Delegation) -> list:
        # 无 claude 环境时，演示三类典型 Web 漏洞的校验闭环。
        # 部分 finding 携带真实可复现证据（通过 grounding），部分只留描述（应被降级）。
        return [
            Finding(vuln_class="sqli", description=f"SQL 注入: 参数 id 存在注入",
                    location=f"GET {d.target}/api/item?id=1", confidence="probable",
                    evidence="响应: SQL syntax error near '1' at line 1 —— 注入点回显数据库错误"),
            Finding(vuln_class="ssti", description="模板注入: name 参数 {{7*7}} 回显 49",
                    location=f"POST {d.target}/greet", confidence="probable",
                    evidence="响应: Hello 49 —— 模板表达式被求值并回显"),
            Finding(vuln_class="idor", description="越权: 遍历 userId 可读取他人订单",
                    location=f"GET {d.target}/api/order/1001", confidence="probable",
                    evidence="改 id=1002 仍返回 200 且含他人收货地址（无 oracle，仅描述）"),
        ]


# 便捷实例（供 orchestrator 直接引用）
WEB_SUBAGENT = WebSubagent()