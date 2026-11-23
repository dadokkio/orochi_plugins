# Volatility 3 plugin: Windows ApiHooks (user-mode inline hook detector)
# Inspects exported functions of loaded DLLs for inline JMP/CALL/trampoline hooks using pefile + capstone.

import logging
import struct
from typing import Iterable, List, Optional, Tuple

import capstone
import pefile

from volatility3.framework import exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class ApiHooks(interfaces.plugins.PluginInterface):
    """Detects user-mode inline API hooks in exported DLL functions."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.StringRequirement(
                name="dll",
                description="Optional substring filter on module name (e.g. ntdll.dll)",
                default=None,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
        ]

    @staticmethod
    def _resolve_module(addr: int, modules: List[Tuple[int, int, str]]) -> str:
        for base, end, name in modules:
            if base <= addr < end:
                return name
        return "<unbacked>"

    @staticmethod
    def _inspect_prologue(
        proc_layer,
        func_addr: int,
        mod_base: int,
        mod_end: int,
        cs: capstone.Cs,
        is_64bit: bool,
    ) -> Optional[Tuple[str, int, str]]:
        try:
            code = proc_layer.read(func_addr, 24, pad=False)
        except exceptions.InvalidAddressException:
            return None

        insns = list(cs.disasm(code, func_addr, count=4))
        if not insns:
            return None

        first = insns[0]
        disasm_str = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns[:3])

        # 1. Direct relative JMP / CALL outside module
        if first.mnemonic in ("jmp", "call") and first.operands:
            op = first.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                target = op.imm & (0xFFFFFFFFFFFFFFFF if is_64bit else 0xFFFFFFFF)
                if not (mod_base <= target < mod_end):
                    return (f"Inline {first.mnemonic.upper()}", target, disasm_str)

            # 2. Indirect JMP/CALL [RIP + disp] or [imm] (FF 25 / FF 15)
            elif op.type == capstone.x86.X86_OP_MEM and op.mem.index == 0:
                ptr_addr = None
                if is_64bit and op.mem.base == capstone.x86.X86_REG_RIP:
                    ptr_addr = first.address + first.size + op.mem.disp
                elif not is_64bit and op.mem.base == 0:
                    ptr_addr = op.mem.disp & 0xFFFFFFFF
                if ptr_addr is not None:
                    try:
                        ptr_size = 8 if is_64bit else 4
                        ptr_raw = proc_layer.read(ptr_addr, ptr_size, pad=False)
                        target = struct.unpack("<Q" if is_64bit else "<I", ptr_raw)[0]
                        if target and not (mod_base <= target < mod_end):
                            return (f"Indirect {first.mnemonic.upper()}", target, disasm_str)
                    except exceptions.InvalidAddressException:
                        pass

        # 3. Trampoline: mov reg, <imm>; jmp/call reg
        if len(insns) >= 2 and first.mnemonic in ("mov", "movabs") and insns[1].mnemonic in ("jmp", "call"):
            if (
                len(first.operands) == 2
                and first.operands[0].type == capstone.x86.X86_OP_REG
                and first.operands[1].type == capstone.x86.X86_OP_IMM
                and len(insns[1].operands) == 1
                and insns[1].operands[0].type == capstone.x86.X86_OP_REG
                and first.operands[0].reg == insns[1].operands[0].reg
            ):
                target = first.operands[1].imm & (0xFFFFFFFFFFFFFFFF if is_64bit else 0xFFFFFFFF)
                if not (mod_base <= target < mod_end):
                    return ("MOV+JMP Trampoline", target, disasm_str)

        # 4. Trampoline: push <imm>; ret
        if (
            len(insns) >= 2
            and first.mnemonic == "push"
            and insns[1].mnemonic == "ret"
            and first.operands
            and first.operands[0].type == capstone.x86.X86_OP_IMM
        ):
            target = first.operands[0].imm & (0xFFFFFFFFFFFFFFFF if is_64bit else 0xFFFFFFFF)
            if not (mod_base <= target < mod_end):
                return ("PUSH+RET Trampoline", target, disasm_str)

        return None

    def _generator(self, procs) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        kernel_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        dll_filter = (self.config.get("dll") or "").lower()

        for proc in procs:
            try:
                pid = int(proc.UniqueProcessId)
                proc_name = utility.array_to_string(proc.ImageFileName)
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException:
                continue

            # Collect loaded modules for target resolution
            loaded_mods: List[Tuple[int, int, str]] = []
            try:
                for mod in proc.load_order_modules():
                    try:
                        base = int(mod.DllBase)
                        size = int(mod.SizeOfImage)
                        mname = mod.BaseDllName.get_string()
                        if base and size:
                            loaded_mods.append((base, base + size, mname))
                    except exceptions.InvalidAddressException:
                        continue
            except exceptions.InvalidAddressException:
                continue

            for mod_base, mod_end, mod_name in loaded_mods:
                if dll_filter and dll_filter not in mod_name.lower():
                    continue
                mod_size = mod_end - mod_base
                if mod_size <= 0 or mod_size > 128 * 1024 * 1024:
                    continue

                # Read PE headers + export directory via pefile
                try:
                    header = proc_layer.read(mod_base, min(mod_size, 0x1000), pad=True)
                    if not header.startswith(b"MZ"):
                        continue
                    pe_hdr = pefile.PE(data=header, fast_load=True)
                    is_64bit = pe_hdr.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
                    exp_dir = pe_hdr.OPTIONAL_HEADER.DATA_DIRECTORY[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
                    ]
                    if exp_dir.VirtualAddress == 0 or exp_dir.Size == 0:
                        continue
                    image_bytes = proc_layer.read(mod_base, mod_size, pad=True)
                    pe = pefile.PE(data=image_bytes, fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                    )
                except Exception:
                    continue

                if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    continue

                cs = capstone.Cs(
                    capstone.CS_ARCH_X86,
                    capstone.CS_MODE_64 if is_64bit else capstone.CS_MODE_32,
                )
                cs.detail = True

                for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if sym.forwarder is not None or not sym.address:
                        continue
                    func_addr = mod_base + sym.address
                    res = self._inspect_prologue(
                        proc_layer, func_addr, mod_base, mod_end, cs, is_64bit
                    )
                    if res is None:
                        continue
                    hook_type, target_addr, disasm_str = res
                    target_mod = self._resolve_module(target_addr, loaded_mods)
                    func_name = (
                        sym.name.decode("utf-8", errors="replace")
                        if sym.name
                        else f"Ordinal_{sym.ordinal}"
                    )
                    yield (
                        0,
                        (
                            pid,
                            proc_name,
                            mod_name,
                            func_name,
                            hook_type,
                            format_hints.Hex(func_addr),
                            format_hints.Hex(target_addr),
                            target_mod,
                            disasm_str,
                        ),
                    )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        procs = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Module", str),
                ("Function", str),
                ("Hook Type", str),
                ("Hook Address", format_hints.Hex),
                ("Target Address", format_hints.Hex),
                ("Target Module", str),
                ("Disassembly", str),
            ],
            self._generator(procs),
        )
