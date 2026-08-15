"""AutoSecAgent CLI 入口。

用法示例：
  python -m autosec.cli --target example.com
  python -m autosec.cli --target app.apk --surface mobile
  python -m autosec.cli --target api.carnet.com --auth auth.yaml
  python -m autosec.cli --list-surfaces
  python -m autosec.cli --version
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .classifier import classify, display
from .config import Config
from .orchestrator import Orchestrator

SURFACES = ("web", "mobile", "iot")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autosec",
        description="AutoSecAgent — 车联网/Web/移动端 三面一体化漏洞挖掘 Agent",
    )
    p.add_argument("--version", action="version", version=f"autosec {__version__}")
    p.add_argument("--target", "-t", help="目标：域名/URL/IP/APK/IPA/固件/车云地址")
    p.add_argument("--surface", nargs="*", choices=SURFACES,
                   help="手动指定攻击面（覆盖自动分类）")
    p.add_argument("--auth", "-a", help="授权声明文件路径 (YAML/JSON)")
    p.add_argument("--config", help="配置文件路径 (默认 config.yaml)")
    p.add_argument("--no-auth", action="store_true", help="关闭授权硬校验（不推荐）")
    p.add_argument("--ctf-mode", action="store_true",
                   help="CTF/靶场模式：注入场景边界 + 本地 CTF 知识包 + 自学习回灌")
    p.add_argument("--classify-only", "--inspect", action="store_true",
                   help="仅分类并展示目标类型，不执行委派")
    p.add_argument("--batch", help="批量模式：从文件读取目标列表（每行一个），去重+续跑")
    p.add_argument("--recon", action="store_true",
                   help="资产测绘：对目标域做被动子域枚举（crt.sh）+ 归属校验 + 去重")
    p.add_argument("--dry-run", action="store_true",
                   help="无 claude 环境时用示例 finding 演示闭环（离线验证）")
    p.add_argument("--list-surfaces", action="store_true", help="列出支持的攻击面")
    p.add_argument("--check-env", action="store_true",
                   help="诊断真实运行环境（claude CLI + API key + .env）")
    return p


def _check_env(cfg: Config) -> int:
    """诊断引擎真实运行环境。"""
    import shutil
    print("AutoSecAgent 引擎环境诊断")
    print("=" * 40)
    claude = shutil.which(cfg.engine_cmd)
    print(f"[claude CLI] {'✓ ' + claude if claude else '✗ 未找到 ' + cfg.engine_cmd}")
    print(f"[provider  ] {cfg.engine_provider}")
    print(f"[endpoint  ] {cfg.engine_base_url or '(由 provider 预设)'}")
    print(f"[model     ] {cfg.engine_model or '(由 provider 预设)'}")
    print(f"[api_key   ] {'✓ 已配置' if cfg.engine_api_key else '✗ 未配置 (AUTOSEC_ENGINE_API_KEY / .env)'}")
    ok, msg = cfg.engine_ready()
    print(f"[engine    ] {'✓ ' + msg if ok else '✗ ' + msg}")
    env = cfg.engine_env()
    print(f"[注入变量  ] {len([k for k, v in env.items() if v])} 个有效 (ANTHROPIC_*)")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_surfaces:
        print("AutoSecAgent 支持的攻击面:")
        print("  web    - Web / API 资产")
        print("  mobile - 移动端 APP (Android/iOS)")
        print("  iot    - 车联网 (车载 APP / 车云平台 / 固件)")
        return 0

    cfg = Config.load(args.config)
    if args.no_auth:
        cfg.auth_required = False
    if args.ctf_mode:
        cfg.ctf_mode = True
    if args.surface:
        cfg.attacksurfaces = args.surface

    if args.check_env:
        return _check_env(cfg)

    # 批量模式：从文件读目标列表，去重 + 续跑（无需 --target）
    if args.batch:
        try:
            with open(args.batch, encoding="utf-8") as fh:
                targets = [ln.strip() for ln in fh if ln.strip()]
        except OSError as e:
            print(f"错误: 无法读取批量目标文件 {args.batch}: {e}", file=sys.stderr)
            return 2
        if not targets:
            print("错误: 批量目标文件为空", file=sys.stderr)
            return 2
        orch = Orchestrator(cfg)
        try:
            stats, sched = orch.run_batch(
                targets, surfaces=args.surface or None,
                auth_file=args.auth, dry_run=args.dry_run)
            print(f"\n批量完成: {stats}  剩余任务 {sum(sched.summary().values()) - sched.summary().get('done', 0)}")
        finally:
            orch.close()
        return 0

    # 资产测绘模式：被动子域枚举 + 归属校验 + 去重（只读）
    if args.recon:
        if not args.target:
            print("错误: 资产测绘需要 --target（域名）", file=sys.stderr)
            return 2
        from .asset_recon import AssetRecon
        assets = AssetRecon().expand(args.target)
        print(f"资产测绘结果（种子 {args.target}，共 {len(assets)} 个，已归属校验去重）:")
        for a in assets:
            print(f"  [{a.type:<9}] {a.host:<40} src={a.source:<7} conf={a.confidence:.0%}")
        return 0

    if not args.target:
        print("错误: 缺少 --target。使用 --help 查看用法。", file=sys.stderr)
        return 2

    # 仅分类模式：不校验授权，不委派
    if args.classify_only:
        clf = classify(args.target)
        print(display(clf))
        return 0

    orch = Orchestrator(cfg)
    try:
        results = orch.run(args.target, auth_file=args.auth, dry_run=args.dry_run)
        _print_results(results)
    except PermissionError as e:
        print(f"[拒绝] {e}", file=sys.stderr)
        return 1
    finally:
        orch.close()
    return 0


def _print_results(results) -> None:
    """打印各子代理的 confirmed 漏洞清单。"""
    for res in results:
        if not res.confirmed:
            print(f"\n[{res.surface}] 无 confirmed 漏洞（{len(res.findings)} 个 finding 未通过校验）")
            continue
        print(f"\n[{res.surface}] confirmed 漏洞 {len(res.confirmed)} 个:")
        for c in res.confirmed:
            print(f"  ✓ [{c.vuln_class}] {c.statement}")
            print(f"      位置: {c.location}  置信度: {c.confidence:.0%}")
            for r in c.reasons:
                print(f"      依据: {r}")


if __name__ == "__main__":
    raise SystemExit(main())