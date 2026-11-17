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
NDK = None

# 找 NDK
cands = []
for base in (Path.home() / "Library/Android/sdk/ndk",):
    if base.is_dir():
        for v in sorted(base.iterdir(), reverse=True):
            cands.append(v)
for v in cands:
    for host in ("darwin-x86_64", "linux-x86_64", "darwin-arm64"):
        cc = v / "toolchains/llvm/prebuilt" / host / "bin" / "aarch64-linux-android30-clang"
        if cc.is_file():
            NDK = (v, host, cc)
            break
    if NDK:
        break
if not NDK:
    print("找不到 Android NDK", file=sys.stderr)
    sys.exit(2)

ndk, host, cc = NDK
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
env["PAGE_LEN_CONST"] = str(page_len)
env["SIGNO_CONST"] = env.get("MDA_SIGNO", "11")
r = subprocess.run([str(cc), "-c",
                    f"-DPAGE_ADDR_LO_CONST={env['PAGE_ADDR_LO_CONST']}",
                    f"-DPAGE_ADDR_HI_CONST={env['PAGE_ADDR_HI_CONST']}",
                    f"-DPAGE_LEN_CONST={env['PAGE_LEN_CONST']}",
                    f"-DSIGNO_CONST={env['SIGNO_CONST']}",
                    "-o", str(obj), str(src)],
                   capture_output=True, text=True, env=env)
if r.returncode != 0:
    print(r.stdout, r.stderr, file=sys.stderr)
    sys.exit(3)

# 2) 链接成单一连续段（.text 紧跟 .data）
#    必须这样：注入时 payload 和 shared_slot 要在同一块连续内存里，
#    而直接 objcopy .o 会把 .text 与 .data 分成两段，符号偏移对不上。
ld = cc.parent / "ld"
elf = HERE / "mda_payload.elf"
r = subprocess.run([
    str(ld), "-r", "-o", str(obj), str(obj),
], capture_output=True, text=True)
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
    sys.exit(4)

# 3) 转成裸二进制（objcopy）
objcopy = cc.parent / "llvm-objcopy"
r = subprocess.run([str(objcopy), "-O", "binary",
                    "--only-section=.payload",
                    "--only-section=.payload_data",
                    str(elf), str(binf)],
                   capture_output=True, text=True)
if r.returncode != 0:
    print("objcopy 失败:", r.stderr, file=sys.stderr)
    sys.exit(5)

data = binf.read_bytes()

# 4) 找符号偏移（相对链接后二进制）
r = subprocess.run([str(cc.parent / "llvm-nm"), str(elf)], capture_output=True, text=True)
entry_off = shared_off = handler_off = restorer_off = slot_off = ran_off = None
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) >= 3:
        addr, typ, name = parts[0], parts[-2], parts[-1]
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
        elif name == "handler_entry":
            handler_off = int(addr, 16)
        elif name == "slot_page":
            slot_off = int(addr, 16)
        elif name == "handler_ran":
            ran_off = int(addr, 16)

if entry_off is None or shared_off is None or handler_off is None:
    print(f"找不到符号: entry={entry_off} shared={shared_off}", file=sys.stderr)
    print(r.stdout, file=sys.stderr)
    sys.exit(5)

# 4) 生成 C 文件
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
