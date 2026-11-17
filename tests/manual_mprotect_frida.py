"""验证：frida 能不能在目标进程里做 mprotect + 捕获自己制造的 SIGSEGV。

## 为什么必须实测

之前项目里记着一条结论：
    "Process.setExceptionHandler 收不到 SIGSEGV（hits=0）"

但那条是在**硬件观察点（perf_event）**场景下测的——那种 SIGSEGV
由内核在用户态返回前投递，frida 收不到。

**mprotect 方案完全不同**：SIGSEGV 是我们自己把页改成只读后、
由写入指令直接触发的，属于**同步用户态异常**，走的是正常的
信号投递路径。两者不是一回事，不能拿旧结论套。

所以这个实验必须真跑一遍。

## 验证什么

1. frida 的 Memory.protect() 能不能把目标页改成只读
2. Process.setExceptionHandler 能不能收到我们制造的 SIGSEGV
3. handler 里能不能读到**写入前**的内容（这才是关键）
4. 能不能拿到完整寄存器（pc/lr/sp）
5. 恢复写权限后，目标能不能继续正常跑（不崩）

## 用法

    .venv/bin/python tests/manual_mprotect_frida.py <serial> <pid> <addr>
"""

import json
import sys
import time

import frida


JS = r"""
// 在目标进程里：把一页设为只读，装 SIGSEGV handler，触发写入，看能不能抓到。
const page = ptr(__PAGE__);
const target = ptr(__TARGET__);
const size = __SIZE__;

const results = {};

// ---- 1. 装异常处理器 ----
const installed = Process.setExceptionHandler(details => {
    const ctx = details.context;
    results.got_sigsegv = true;
    results.fault_addr = details.address ? details.address.toString() : null;

    // 关键：此刻写入指令**还没执行**，所以这里读到的还是旧值
    try {
        results.before_hex = hexdump(target, { length: size, header: false, ansi: false });
    } catch (e) {
        results.before_err = String(e);
    }

    // 寄存器（arm64）
    try {
        results.regs = {
            pc: ctx.pc ? ctx.pc.toString() : null,
            lr: ctx.lr ? ctx.lr.toString() : null,
            sp: ctx.sp ? ctx.sp.toString() : null,
            x0: ctx.x0 ? ctx.x0.toString() : null,
            x1: ctx.x1 ? ctx.x1.toString() : null,
            x8: ctx.x8 ? ctx.x8.toString() : null,
        };
    } catch (e) {
        results.regs_err = String(e);
    }

    // 恢复可写，让那条写指令能完成
    try {
        Memory.protect(page, 4096, 'rwx');
        results.reprotect_ok = true;
    } catch (e) {
        results.reprotect_err = String(e);
    }
    return false;   // false = 交回系统处理（让写指令继续）
});

// ---- 2. 把目标页设为只读 ----
try {
    Memory.protect(page, 4096, 'r');
    results.protect_ok = true;
} catch (e) {
    results.protect_err = String(e);
    send({ done: true, results: results });
}

// ---- 3. 触发一次写入 ----
setTimeout(function () {
    try {
        const ab = target.readByteArray(size);
        results.before_static = Array.from(new Uint8Array(ab))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        results.read_err = String(e);
    }
    send({ stage: 'armed', results: results });
}, 100);

// 真实写入由外部触发；这里只负责布防
send({ stage: 'armed', results: results });
"""


def run(serial: str, pid: int, addr: int, size: int = 8):
    dev = frida.get_device(serial, timeout=15)
    sess = dev.attach(int(pid))
    page = addr & ~0xFFF
    src = (JS.replace("__PAGE__", str(page))
              .replace("__TARGET__", str(addr))
              .replace("__SIZE__", str(size)))
    script = sess.create_script(src)
    box = {}

    def on_msg(msg, data):
        p = msg.get("payload")
        if isinstance(p, dict):
            box.update(p)

    script.on("message", on_msg)
    script.load()
    time.sleep(1.0)
    print(json.dumps({"stage": "armed", "box": box}, ensure_ascii=False, indent=2))
    return sess, script, box


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        print("用法: manual_mprotect_frida.py <serial> <pid> <addr> [size]")
        return 1
    serial, pid, addr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3], 16)
    size = int(sys.argv[4]) if len(sys.argv) > 4 else 8

    sess, script, box = run(serial, pid, addr, size)
    print("--- 布防完成，现在从外部写一次目标内存 ---")
    print(f"    地址 0x{addr:x}，写 8 字节")
    # 外部写入：用 mda 的 read_runtime_memory 同款路径（adb dd 写不进去），
    # 这里改用 frida 自己的 Process.writeByteArray
    js = ("var v = new Uint8Array([0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe]);"
          f"Process.writeByteArray(ptr({addr}), v);"
          "send({stage:'wrote'});")
    s2 = sess.create_script(js)
    got = {}

    def on2(msg, data):
        p = msg.get("payload")
        if isinstance(p, dict):
            got.update(p)

    s2.on("message", on2)
    s2.load()
    time.sleep(1.5)
    print(json.dumps({"after": got, "box": box}, ensure_ascii=False, indent=2))
    print()
    if box.get("got_sigsegv"):
        print("=== 结论：frida 收到了自己制造的 SIGSEGV ===")
        print("  写入前内容:", box.get("before_hex"))
        print("  寄存器:", json.dumps(box.get("regs"), ensure_ascii=False))
    else:
        print("=== 结论：frida 没收到 SIGSEGV（与旧记录一致）===")
    try:
        sess.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
