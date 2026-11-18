"""Native 代码 patch 插件（通用能力）。

## 解决什么问题

断点只能"看"，不能"改"。逆向时常需要：
  · 把一条条件跳转改成无条件跳转（绕过校验）
  · 把 bl 改成 nop（跳过某个调用）
  · 把返回值改成常量（mov w0, #1; ret）
  · 把加密的代码段临时解密后再读

本插件用 frida 的 `Memory.protect` + `Memory.write` 直接改目标内存，
改完可以恢复原字节。

## 为什么可行（真机验证过）

`Memory.protect` 在 mda 里已验证可用（`tests/manual_mprotect_frida.py`
实测 protect_ok=true）。而 `Process.setExceptionHandler` 那条路不通——
所以本插件**只做写，不做 SIGSEGV 捕获**。

## 能力边界（诚实说明）

  · 改的是**运行时内存**，不落盘——重启 App 即恢复
  · 改代码页前会先改权限为 RWX，写完再改回原权限
  · **不做** arm64 指令编码（调用方自己给机器码 hex，
    或用 helper 里的 `assemble` 动作走 capstone 反查）
  · 加固 App 可能有 CRC 自校验，改完可能触发崩溃/重启——这是预期风险

## 通用性

纯 frida Memory API 封装，不含任何具体 so/地址/指令特征。
"""
from __future__ import annotations

from server.core.plugins import PluginBase

_JS_PATCH = r"""
(function () {
    var ADDR = __ADDR__;
    var DATA = __DATA__;
    var RESTORE = __RESTORE__;
    var out = {ok: false};

    try {
        var p = ptr(ADDR);

        // (5) frida 17 的 API 变了（真机枚举确认）：
        //     `ptr().write` / `Memory.write` / `Memory.readByteArray` **都不存在**，
        //     Memory 只剩 alloc / dup / patchCode / scan。
        //     patchCode 是官方推荐的代码改写入口，它会自动处理
        //     目标页的写权限与指令缓存刷新。
        var u8 = new Uint8Array(DATA.length);
        for (var i = 0; i < DATA.length; i++) { u8[i] = DATA[i]; }

        // 用 Memory.scan 取原字节（patchCode 不回传旧值）
        var old = null;
        try {
            var sizeForScan = DATA.length;
            Memory.scan(p, sizeForScan, Array.from(u8).map(function (b) {
                return ('0' + b.toString(16)).slice(-2);
            }).join(' '), {
                onMatch: function (address, size) {
                    // 用 scan 的回调拿不到"原字节"，这里只用于确认存在
                },
                onComplete: function () {}
            });
        } catch (e) { out.scan_error = String(e); }

        // 真正写入
        try {
            Memory.patchCode(p, u8.length, function (code) {
                code.writeByteArray(Array.from(u8));
            });
            out.wrote = true;
        } catch (e) { out.write_error = String(e); }

        // 校验放到 Python 侧做（外部读 /proc/pid/mem，同步可靠）

        out.ok = !!out.wrote;
    } catch (e) {
        out.error = String(e);
    }
    send(out);
})();
"""


class Plugin(PluginBase):
    name = "patch_memory"
    description = "改目标进程内存字节（native patch / 解密后重读 / 恢复原字节）"
    usage = ("args: {so: str, addr: str|int, hex: str (要写入的字节), "
             "serial: str, pid: int, restore: bool=false, "
             "verify: bool=true}")

    def run(self, session, args: dict):
        serial = args.get("serial")
        pid = args.get("pid")
        if not serial or not pid:
            return {"error": "需要 serial 与 pid（目标必须已确认）",
                    "code": "NEED_TARGET"}
        addr = args.get("addr")
        hexs = str(args.get("hex") or "").strip().replace(" ", "")
        if addr is None or not hexs:
            return {"error": "需要 addr 与 hex", "code": "BAD_ARGS"}
        try:
            data = bytes.fromhex(hexs)
        except ValueError:
            return {"error": f"hex 不是合法十六进制：{hexs[:40]}",
                    "code": "BAD_HEX"}

        a = int(str(addr), 16) if isinstance(addr, str) and \
            str(addr).lower().startswith("0x") else int(addr)

        # (7) restore=true 时：先读旧字节 → 写入 → 再由 Python 写回旧值
        old_bytes = b""
        if args.get("restore"):
            try:
                from server.dyn.inject import read_target_mem

                old_bytes = read_target_mem(str(serial), int(pid), a, len(data))
            except Exception:                             # noqa: BLE001
                old_bytes = b""

        js = (_JS_PATCH
              .replace("__ADDR__", f'"{hex(a)}"')
              .replace("__DATA__", "[" + ",".join(str(b) for b in data) + "]")
              .replace("__RESTORE__", "true" if args.get("restore") else "false"))

        try:
            import frida

            dev = frida.get_device(str(serial), timeout=15)
            sess = dev.attach(int(pid))
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"attach 失败：{exc}",
                    "code": "ATTACH_FAILED"}

        try:
            script = sess.create_script(js)
            box: dict = {}

            def _on_message(msg, data):
                # (3) frida 回调是 (message, data)：
                #     message = {'type':'send'|'error', 'payload': {...}}
                #     data 是二进制附加数据（通常 None）
                if not isinstance(msg, dict):
                    return
                if msg.get("type") == "error":
                    box["error"] = msg.get("description") or str(msg)
                    return
                payload = msg.get("payload")
                if isinstance(payload, dict):
                    box.update(payload)

            script.on("message", _on_message)
            script.load()
            import time

            for _ in range(100):
                if box:
                    break
                time.sleep(0.05)
            # (7) 用 tracer 的异步卸载：同步 unload 在 frida 17 会永久阻塞
            try:
                from server.dyn.tracer import _detach_async

                _detach_async(sess)
            except Exception:                             # noqa: BLE001
                pass
        except Exception as exc:                          # noqa: BLE001
            return {"error": f"执行失败：{exc}", "code": "PATCH_FAILED"}
        finally:
            # (7) 同上：detach 也走异步，避免 MCP 调用永不返回
            try:
                from server.dyn.tracer import _detach_async

                _detach_async(sess)
            except Exception:                             # noqa: BLE001
                pass

        if not box:
            return {"error": "脚本未返回结果（超时）", "code": "NO_RESULT"}
        box["ok"] = bool(box.get("ok"))
        box["addr"] = hex(a)
        box["size"] = len(data)
        # (6) 外部读回校验（同步可靠）
        if box.get("ok") and args.get("verify", True):
            try:
                from server.dyn.inject import read_target_mem

                back = read_target_mem(str(serial), int(pid), a, len(data))
                box["readback"] = back.hex()
                box["verified"] = (back == data)
                if not box["verified"]:
                    box["verify_note"] = ("读回字节与写入不一致——"
                                          "可能是加固的 CRC 自校验已还原，"
                                          "或该页被 COW 分离")
            except Exception as exc:                      # noqa: BLE001
                box["verify_error"] = f"{type(exc).__name__}: {exc}"
        box["note"] = ("改的是运行时内存，不落盘——重启 App 即恢复。"
                       "加固 App 若有 CRC 自校验，改完可能崩溃。")
        # (7) restore=true：把原字节记下来并写回（真正的恢复）
        if args.get("restore") and old_bytes:
            try:
                from server.dyn.inject import write_target_mem

                write_target_mem(str(serial), int(pid), a, old_bytes)
                box["restored"] = True
                box["restored_hex"] = old_bytes.hex()
            except Exception as exc:                      # noqa: BLE001
                box["restore_error"] = f"{type(exc).__name__}: {exc}"
        return box
