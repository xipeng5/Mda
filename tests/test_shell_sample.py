"""回归测试：节表损坏样本上的字节搜索 + 会话转发链路。

运行：.venv/bin/python tests/test_shell_sample.py

为什么单独一个文件：
  壳处理过的 dump so（节表被抹）与正常 so 是两条完全不同的代码路径，
  test_e2e.py 用的 liblog/libbase 全是健康节表，覆盖不到这里。
  这两个 bug 都只在壳样本上暴露，所以样本与断言一起固化。

历史问题（2026-10-30 修复前）：
  - search_bytes 在节表为空的样本上恒返回 count:0（连单字节 d2 也搜不到），
    会让人误判「样本里没有该字节/没有分发器」。
  - 工具调用与 GUI 是两套会话（MCP 进程各持一份 Session 单例），
    AI 的分析在界面上完全不可见，且 AI 侧毫无察觉。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 本测试验证「本进程内」的行为，必须关闭转发，否则会打到运行中的 GUI。
os.environ["MDA_IS_GUI"] = "1"

from mcp_server.tools import _session, search_bytes  # noqa: E402

SAMPLE = Path(
    "/Users/waterclean/Desktop/ProJect/py/pythonProject1/咸鱼web/hooks/out/sg/"
    "libsgmainso-6.7.260202.so"
)
PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [通过] {name}")
    else:
        FAIL += 1
        print(f"  [失败] {name} {detail}")


def main() -> int:
    if not SAMPLE.exists():
        print(f"样本不存在，跳过：{SAMPLE}")
        return 0

    print("== 壳样本加载 ==")
    so = _session.add(str(SAMPLE))
    check("节表为空（壳特征）", len(so.sections) == 0, f"实际 {len(so.sections)}")
    check("PT_LOAD 可执行段可用", len(so.exec_regions()) >= 1,
          f"实际 {len(so.exec_regions())}")
    check("函数已恢复", len(so.functions) > 1000, f"实际 {len(so.functions)}")

    print("== search_bytes 兜底（修复前恒为 0）==")
    r = json.loads(search_bytes(so.name, "d2", 5))
    check("单字节可搜到", r["count"] > 0, f"count={r['count']}")
    check("标记为段表兜底", r.get("scan_mode", "").startswith("PT_LOAD"),
          str(r.get("scan_mode")))

    r2 = json.loads(search_bytes(so.name, "00 02 1f d6", 10))
    check("br x16 可搜到", r2["count"] > 0, f"count={r2['count']}")
    addrs = {m["addr"] for m in r2["matches"]}
    # 这些地址来自独立的 PT_LOAD 直扫结果，是分发器模板所在位置
    check("命中已知分发器地址 0x5201c", "0x5201c" in addrs, str(sorted(addrs)[:5]))

    print("== 转发链路可判定 ==")
    from mcp_server import link

    check("GUI 进程自身不转发（防自环）", link.should_forward() is False)
    check("GUI 进程视为同会话", link.gui_online() is True)

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
