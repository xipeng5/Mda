"""公共数据结构定义（Contracts Layer）。

所有模块共享的类型，core/ 与 ui/、mcp_server/ 都依赖此模块。
不依赖任何第三方库，可独立导入。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Arch(IntEnum):
    """目标架构，对应 ELF e_machine。"""

    UNKNOWN = 0
    ARM32 = 40  # EM_ARM
    ARM64 = 183  # EM_AARCH64
    X86 = 3
    X86_64 = 62


class SymbolKind(IntEnum):
    """符号来源与性质。"""

    EXPORT = 0  # .dynsym 中已定义、非 UNDEF
    IMPORT = 1  # .dynsym 中 UNDEF
    LOCAL = 2  # .symtab 中（stripped 则无）
    PLT = 3  # PLT stub 对应的导入符号
    INTERNAL = 4  # 由函数发现推导出的未命名函数


@dataclass(frozen=True)
class Section:
    """ELF section，name 为空串表示无名字段。"""

    name: str
    addr: int  # sh_addr
    size: int  # sh_size
    offset: int  # sh_offset
    sec_type: int  # sh_type
    is_exec: bool  # SHF_EXECINSTR
    is_write: bool  # SHF_WRITE

    @property
    def end(self) -> int:
        return self.addr + self.size

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end


@dataclass(frozen=True)
class Symbol:
    """符号。addr 对 IMPORT 为 0。"""

    name: str
    addr: int
    size: int
    kind: SymbolKind
    is_func: bool = True
    source: str = ""  # 产生该符号的 section 名，便于溯源


@dataclass
class Instruction:
    """单条反汇编结果。addr 为虚拟地址，bytes 为文件真实字节。"""

    addr: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    # 由语义层填充
    call_target: Optional[int] = None  # bl/b 的直接目标
    is_call: bool = False
    is_ret: bool = False
    is_jump: bool = False
    ref_addr: Optional[int] = None  # adrp+add / adrp+ldr 解析出的数据地址

    @property
    def text(self) -> str:
        """objdump 风格文本。"""
        return f"{self.mnemonic} {self.op_str}".strip()


@dataclass
class Function:
    """函数。addr/size 来自 FDE 或推导。"""

    addr: int
    size: int
    name: str = ""
    # 反汇编填充
    instructions: list[Instruction] = field(default_factory=list)
    # 引用分析填充
    calls: list[int] = field(default_factory=list)  # 调用的目标地址（去重）
    string_refs: list[int] = field(default_factory=list)  # 引用的 rodata 地址（去重）
    # 元信息
    discovered_by: str = "fde"  # fde | bl_target | prologue
    is_export: bool = False
    is_import: bool = False  # PLT 导入符号，非真实函数体
    so_name: str = ""  # 所属 so，跨 so 分析时必需

    @property
    def end(self) -> int:
        return self.addr + self.size

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end


@dataclass
class StringRef:
    """提取到的字符串。addr 为虚拟地址。"""

    addr: int
    value: str
    section: str
    # 哪些函数引用了它，跨 so 查询时用
    referenced_by: list[int] = field(default_factory=list)


@dataclass
class Relocation:
    """重定位记录。"""

    offset: int  # r_offset，通常是 GOT 槽地址
    rtype: int  # r_info 低 32 位
    sym_idx: int  # r_info 高 32 位
    sym_name: str = ""
    addend: int = 0
