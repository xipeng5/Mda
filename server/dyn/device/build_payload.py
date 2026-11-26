#!/usr/bin/env python3
"""把 mda_payload.S 编译成二进制，并生成注入器需要的 C 头。

为什么需要这一步：注入码必须在目标进程里执行，而目标进程里没有
符号、没有重定位、不能调用任何函数——所以 payload 必须是纯机器码，
且所有常量（共享内存偏移、handler 地址）都要**编译期固定**。

生成 mda_payload_bin.c，内容是：
  · payload 的机器码字节数组
  · payload_entry 在数组里的偏移
  · shared_slot 在数组里的偏移
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent          # 项目根


# (3) 第三次修改（2026-11-26）
# bug 原因：① 顶层代码直接执行编译和 sys.exit()，导入本模块会产生副作用；
#           ② 符号解析循环 L129-134 存在重复的 elif 分支（handler_entry/slot_page/handler_ran），
#              且缺少对 restorer_off/slot_off/ran_off 的空值校验。
# 解决方案：将构建逻辑封装进 main() + if __name__ == "__main__"，删除重复 elif，
#           补齐全部符号存在性检查。
def _find_ndk():
    """查找本机安装的 Android NDK 及 arm64 clang 路径。"""
    cands = []
    env_ndk = os.environ.get("ANDROID_NDK", "").strip()
    if env_ndk:
        p = Path(env_ndk)
        if p.is_dir():
            cands.append(p)
    for base in (Path.home() / "Library/Android/sdk/ndk",
                 Path.home() / "Android/Sdk/ndk",
                 Path("/usr/local/share/android-ndk")):
        if base.is_dir():
            for v in sorted(base.iterdir(), reverse=True):
                cands.append(v)
    for v in cands:
        for host in ("darwin-x86_64", "linux-x86_64", "darwin-arm64"):
            cc = v / "toolchains/llvm/prebuilt" / host / "bin" / "aarch64-linux-android30-clang"
            if cc.is_file():
                return (v, host, cc)
    return None


def main() -> int:
    """编译 mda_payload.S 为裸机器码并生成 mda_payload_bin.c。"""
    ndk_info = _find_ndk()
    if not ndk_info:
        print("找不到 Android NDK", file=sys.stderr)
        return 2

    ndk, host, cc = ndk_info
    print(f"用 NDK: {ndk.name} / {host}")

    src = HERE / "mda_payload.S"
    obj = HERE / "mda_payload.o"
    binf = HERE / "mda_payload.bin"

    # 1) 汇编（常量由环境变量传入，编译期替换）
    env = dict(os.environ)
    page_addr = int(env.get("MDA_PAGE_ADDR", "0"), 0)
    page_len = int(env.get("MDA_PAGE_LEN", "4096"), 0)
    env["PAGE_ADDR_LO_CONST"] = str(page_addr & 0xffff)
    env["PAGE_ADDR_HI_CONST"] = str((page_addr >> 16) & 0xffff)
    # (2) 第二次修改（2026-11-17）：补 bit32/48，否则高地址只能构造到 bit31
    env["PAGE_ADDR_B2_CONST"] = str((page_addr >> 32) & 0xffff)
    env["PAGE_ADDR_B3_CONST"] = str((page_addr >> 48) & 0xffff)
    env["PAGE_LEN_CONST"] = str(page_len)
    env["SIGNO_CONST"] = env.get("MDA_SIGNO", "11")
    r = subprocess.run([str(cc), "-c",
                        f"-DPAGE_ADDR_LO_CONST={env['PAGE_ADDR_LO_CONST']}",
                        f"-DPAGE_ADDR_HI_CONST={env['PAGE_ADDR_HI_CONST']}",
                        f"-DPAGE_ADDR_B2_CONST={env['PAGE_ADDR_B2_CONST']}",
                        f"-DPAGE_ADDR_B3_CONST={env['PAGE_ADDR_B3_CONST']}",
                        f"-DPAGE_LEN_CONST={env['PAGE_LEN_CONST']}",
                        f"-DSIGNO_CONST={env['SIGNO_CONST']}",
                        "-o", str(obj), str(src)],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        return 3

    # 2) 链接成单一连续段（.text 紧跟 .data）
    #    必须这样：注入时 payload 和 shared_slot 要在同一块连续内存里，
    #    而直接 objcopy .o 会把 .text 与 .data 分成两段，符号偏移对不上。
    ld = cc.parent / "ld"
    elf = HERE / "mda_payload.elf"
    subprocess.run([str(ld), "-r", "-o", str(obj), str(obj)],
                   capture_output=True, text=True)
    # 用链接脚本把两个段拼起来
    linker = HERE / "mda_payload.lds"
    linker.write_text(
        "SECTIONS\n"
        "{\n"
        "  . = 0;\n"
        "  .payload : { *(.text) *(.text.*) }\n"
        "  .payload_data : { *(.data) *(.data.*) }\n"
        "  /DISCARD/ : { *(.comment) *(.note*) *(.rela*) }\n"
        "}\n",
        encoding="utf-8")
    r = subprocess.run([
        str(ld), "-T", str(linker), "-o", str(elf), str(obj), "--defsym=__start_payload=0",
    ], capture_output=True, text=True)
    if r.returncode != 0:
        print("link 失败:", r.stdout, r.stderr, file=sys.stderr)
        return 4

    # 3) 转成裸二进制（objcopy）
    objcopy = cc.parent / "llvm-objcopy"
    r = subprocess.run([str(objcopy), "-O", "binary",
                        "--only-section=.payload",
                        "--only-section=.payload_data",
                        str(elf), str(binf)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("objcopy 失败:", r.stderr, file=sys.stderr)
        return 5

    data = binf.read_bytes()

    # 4) 找符号偏移（相对链接后二进制）
    r = subprocess.run([str(cc.parent / "llvm-nm"), str(elf)], capture_output=True, text=True)
    entry_off = shared_off = handler_off = restorer_off = slot_off = ran_off = None
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            addr, _typ, name = parts[0], parts[-2], parts[-1]
            if name == "payload_entry":
                entry_off = int(addr, 16)
            elif name == "shared_slot":
                shared_off = int(addr, 16)
            elif name == "handler_entry":
                handler_off = int(addr, 16)
            elif name == "slot_page":
                slot_off = int(addr, 16)
            elif name == "handler_ran":
                ran_off = int(addr, 16)
            elif name == "restorer_entry":
                restorer_off = int(addr, 16)

    if any(v is None for v in (entry_off, shared_off, handler_off,
                               restorer_off, slot_off, ran_off)):
        print(f"找不到必要符号: entry={entry_off} shared={shared_off} "
              f"handler={handler_off} restorer={restorer_off} "
              f"slot={slot_off} ran={ran_off}", file=sys.stderr)
        print(r.stdout, file=sys.stderr)
        return 5

    # 5) 生成 C 文件
    out = HERE / "mda_payload_bin.c"
    lines = [
        "/* 自动生成，请勿手改 —— 由 build_payload.py 从 mda_payload.S 生成。",
        " * 重新生成：在 server/dyn/device/ 下跑 python3 build_payload.py",
        " */",
        "const unsigned char mda_payload_bin[] = {",
    ]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    lines.append(f"const unsigned long mda_payload_len = {len(data)};")
    lines.append(f"const unsigned long mda_payload_entry_off = 0x{entry_off:x};")
    lines.append(f"const unsigned long mda_payload_shared_slot_off = 0x{shared_off:x};")
    lines.append(f"const unsigned long mda_payload_handler_off = 0x{handler_off:x};")
    lines.append(f"const unsigned long mda_payload_restorer_off = 0x{restorer_off:x};")
    lines.append(f"const unsigned long mda_payload_handler_len = {len(data) - handler_off};")
    lines.append(f"const unsigned long mda_payload_slot_page_off = 0x{slot_off:x};")
    lines.append(f"const unsigned long mda_payload_handler_ran_off = 0x{ran_off:x};")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"payload: {len(data)} 字节, entry=0x{entry_off:x}, shared=0x{shared_off:x}, "
          f"handler=0x{handler_off:x}, restorer=0x{restorer_off:x}")
    print(f"已生成 {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
