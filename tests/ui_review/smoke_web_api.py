"""Web 版冒烟测试：启动 API → 打所有关键接口 → 断言数据结构 → 退出。

不依赖 pytest（项目环境未装），直接运行：
    .venv/bin/python tests/ui_review/smoke_web_api.py

只读取真实 so（samples/libbase.so），不写任何数据；服务起在随机空闲端口，避免和正在跑的实例打架。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE = os.path.join(ROOT, "samples", "libbase.so")


def free_port() -> int:
    """让系统分配一个空闲端口，避免固定端口被占用导致误判。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get(url: str, timeout: float = 60.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def post(url: str, payload: dict, timeout: float = 120.0):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    if not os.path.isfile(SAMPLE):
        print(f"[SKIP] 缺少样本：{SAMPLE}")
        return 0

    port = free_port()
    env = dict(os.environ, MDA_API_PORT=str(port))
    proc = subprocess.Popen(
        [sys.executable, "-m", "server.api"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    checks: list[tuple[str, bool, str]] = []

    try:
        for _ in range(120):                       # 最多等 12 秒
            try:
                if get(f"{base}/api/health", timeout=1).get("ok"):
                    break
            except Exception:                      # noqa: BLE001 - 未就绪继续等
                time.sleep(0.1)
        else:
            print("[FAIL] API 未启动")
            return 1

        mod = post(f"{base}/api/load", {"path": SAMPLE})["module"]
        checks.append(("load", mod["functions"] > 0, f"{mod['so']} {mod['functions']} 函数"))

        fns = get(f"{base}/api/functions?so={mod['so']}&limit=5")
        checks.append(("functions", fns["total"] > 0 and len(fns["items"]) <= 5, f"total={fns['total']}"))

        addr = fns["items"][0]["addr"]
        dis = get(f"{base}/api/disasm?so={mod['so']}&addr={addr}")
        checks.append(("disasm", len(dis["items"]) > 0, f"{len(dis['items'])} 条指令"))

        xr = get(f"{base}/api/xrefs?so={mod['so']}&addr={addr}")
        checks.append(("xrefs", isinstance(xr["callers"], list), f"{len(xr['callers'])} 入"))

        st = get(f"{base}/api/strings?so={mod['so']}")
        checks.append(("strings", len(st["items"]) > 0, f"{len(st['items'])} 条"))

        ok = all(c[1] for c in checks)
        for name, passed, detail in checks:
            print(f"  {'PASS' if passed else 'FAIL'}  {name:10s} {detail}")
        print("[OK] 全部通过" if ok else "[FAIL] 有失败项")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
