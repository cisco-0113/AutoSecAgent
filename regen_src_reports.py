"""从既有 report JSON 重新生成 SRC 独立漏洞报告。

用途：校验门 oracle 升级 / 报告模板调整后，无需重跑挖掘即可刷新 SRC 报告。
流程：载入 claims -> 修复畸形 claim -> 重过校验门（最新 oracle）-> 按 target
分目录生成（reports/src/<target>/，写入前自动清理旧批次）。

用法：
  python regen_src_reports.py [report.json路径] [--app-version V] [--biz-module M]
不指定 report.json 时取 reports/ 下最新的一份。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT))

from autosec.srcreport import _sanitize_claim, generate_src_reports  # noqa: E402
from autosec.verify import VulnClaim, VulnVerifier  # noqa: E402


def load_claims(report_json: str | Path) -> tuple[str, list[VulnClaim]]:
    d = json.load(open(report_json, encoding="utf-8"))
    claims = []
    for section in ("confirmed", "pending_review"):
        for c in d.get(section) or []:
            claims.append(VulnClaim(
                vuln_class=c.get("vuln_class") or "",
                statement=c.get("statement") or "",
                location=c.get("location") or "",
                poc=c.get("poc") or "",
                evidence=c.get("evidence") or "",
                severity=c.get("severity") or "",
                fix=c.get("fix") or "",
            ))
    return d.get("target") or "", claims


def dedup(claims: list[VulnClaim]) -> list[VulnClaim]:
    out: list[VulnClaim] = []
    for c in claims:
        if all(c.vuln_class != s.vuln_class or c.location != s.location for s in out):
            out.append(c)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report_json", nargs="?", default=None)
    ap.add_argument("--app-version", default="")
    ap.add_argument("--biz-module", default="")
    args = ap.parse_args()

    rj = Path(args.report_json) if args.report_json else \
        max((PROJECT / "reports").glob("*_report.json"), key=lambda p: p.stat().st_mtime)
    target, claims = load_claims(rj)
    claims = dedup([_sanitize_claim(c) for c in claims])

    verifier = VulnVerifier(require_poc=True)
    verified = [verifier.verify(c) for c in claims]

    safe_t = re.sub(r"[^\w.-]+", "_", target)[-60:] or "target"
    out_dir = PROJECT / "reports" / "src" / safe_t
    files = generate_src_reports(
        verified, target=target, report_dir=out_dir, platform="oppo",
        meta={"app_version": args.app_version, "biz_module": args.biz_module},
    )
    print(f"来源: {rj.name}")
    print(f"目标: {target} -> {out_dir}")
    for i, (c, f) in enumerate(zip(verified, files), 1):
        print(f"  [{i}] {c.vuln_class:<22} {c.verdict:<10} conf={c.confidence:.0%}  {Path(f).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
