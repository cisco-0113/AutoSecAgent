"""P5 规模化冒烟测试 — 账号池 / 资产测绘 / 批量调度。

运行: python smoke_test_p5.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from autosec.account_pool import AccountPool
from autosec.asset_recon import AssetRecon, extract_from_text, dedupe
from autosec.scheduler import BatchScheduler

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


# ── 1) 账号池 ──
print("\n[1] 账号池")
pool_yaml = """
accounts:
  - {id: u1, role: owner, username: a@x.com, credential: tok_owner, target: api.x.com}
  - {id: u2, role: attacker, username: b@x.com, credential: tok_att, target: api.x.com}
  - {id: u3, role: admin, username: c@x.com, credential: tok_adm, target: api.x.com}
"""
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
    f.write(pool_yaml)
    pool_path = f.name
pool = AccountPool(pool_path)
check("加载 3 个账号", len(pool.accounts) == 3, f"got {len(pool.accounts)}")
a = pool.acquire("owner", target="api.x.com")
check("acquire 命中 role+target", a is not None and a.id == "u1")
check("acquire 后状态 in_use", a.status == "in_use")
pool.release("u1")
check("release 后恢复 available", pool._by_id("u1").status == "available")
pool.mark_invalid("u3", "封禁")
check("mark_invalid 后不可用", pool._by_id("u3").status == "invalid")
pa, pb = pool.pick_pair("owner", "attacker", target="api.x.com")
check("差分配对同 target", pa is not None and pb is not None and pa.target == pb.target)
check("凭证脱敏指纹不泄露明文", "tok_owner" not in a.fingerprint() and a.fingerprint() != "(空)")

# ── 2) 资产测绘 ──
print("\n[2] 资产测绘")
assets = extract_from_text(
    "api.example.com https://admin.example.com/v1 10.20.30.40 evil.com")
check("提取域名+URL+IP", len(assets) >= 3, f"got {len(assets)}")
deduped = dedupe(assets + [type("A", (), {"host": "API.EXAMPLE.COM", "type": "subdomain", "source": "dns", "confidence": 0.9})()])
check("去重后大小写归一", len(deduped) < len(assets) + 1, f"got {len(deduped)}")
recon = AssetRecon()
check("归属校验：子域命中", recon.in_scope("api.example.com", "example.com"))
check("归属校验：越权横向拒绝", not recon.in_scope("evil.com", "example.com"))
kept = recon.filter_scope(assets, "example.com")
check("filter_scope 剔除越权资产", all("evil.com" not in a.host for a in kept))
check("crt.sh 无网络安全降级为空", isinstance(recon.crt_sh("example.com"), list))

# ── 3) 批量调度 ──
print("\n[3] 批量调度")
with tempfile.TemporaryDirectory() as td:
    state = Path(td) / "batch.jsonl"
    sched = BatchScheduler(state_path=state)
    n = sched.add_targets(["api.example.com", "API.example.com", "api.evil.com"])
    check("去重（大小写归一）", n == 2, f"got {n}")

    calls = []
    def runner(task):
        calls.append(task.target)
        if "evil" in task.target:
            return False, "授权拒绝", 0
        return True, "", 1
    stats = sched.run_all(runner, persist_each=True)
    check("run_all 最终状态 done=1 failed=1",
          stats.get("done", 0) == 1 and stats.get("failed", 0) == 1, str(stats))

    # 续跑：手动模拟「中断」——done 一个、留一个 pending，persist 后从状态文件恢复
    state2 = Path(td) / "batch2.jsonl"
    sched_a = BatchScheduler(state_path=state2)
    sched_a.add_targets(["done.example.com", "pending.example.com"])
    done_task = next(t for t in sched_a.tasks if t.target == "done.example.com")
    sched_a.mark_done(done_task, confirmed=1)
    sched_a.persist()
    # 新调度器从状态恢复，done 跳过，只取 pending
    sched_b = BatchScheduler(state_path=state2)
    nxt = sched_b.next_pending()
    check("续跑跳过 done，取 pending", nxt is not None and nxt.target == "pending.example.com",
          str(nxt.target if nxt else None))

print(f"\n===== 结果: {PASS} 通过 / {FAIL} 失败 =====")
sys.exit(1 if FAIL else 0)
