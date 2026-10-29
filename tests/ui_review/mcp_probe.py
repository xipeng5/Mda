"""MCP 联动探针：模拟一个 AI 客户端，验证"AI 与界面共享同一会话"。

用法（不接命令行参数，端口取环境变量 MDA_MCP_PORT，默认 8765）：
    .venv/bin/python tests/ui_review/mcp_probe.py
"""
from __future__ import annotations

import asyncio
import json
import os


async def main() -> None:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    port = os.environ.get("MDA_MCP_PORT", "8765")
    url = f"http://127.0.0.1:{port}/mcp"
    async with streamable_http_client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as sess:
            await sess.initialize()
            tools = await sess.list_tools()
            print(f"[MCP] 工具数：{len(tools.tools)}")

            res = await sess.call_tool("list_modules", {})
            text = "".join(
                c.text for c in res.content if getattr(c, "type", "") == "text"
            )
            data = json.loads(text)
            names = [m.get("so") or m.get("name") for m in data.get("modules", data if isinstance(data, list) else [])]
            print("[MCP] list_modules ->", names)
            print("[OK] AI 与界面同会话" if names else "[FAIL] 会话里没有模块")

            # 再发一次真实工具调用，用来验证界面是否同步（应产生一条 AI 活动 + 跳转事件）
            if names:
                res2 = await sess.call_tool("disassemble", {"so_name": names[0], "addr": 0x6a1d0})
                _ = res2
                print("[MCP] 已调用 disassemble -> 界面应同步")


if __name__ == "__main__":
    asyncio.run(main())
