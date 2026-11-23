# Volatility 3 plugin: Windows IDT (Interrupt Descriptor Table)
# Inspects CPU Interrupt Descriptor Tables from KPCR.IdtBase and resolves handlers against kernel modules.

import logging
import struct
from typing import Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import kpcrs, modules

vollog = logging.getLogger(__name__)


def decode_idt_entry(raw: bytes, is_64bit: bool) -> Tuple[int, int]:
    """Decodes an x86 (8-byte) or x64 (16-byte) KIDTENTRY into (selector, handler_address)."""
    if is_64bit:
        off_low, selector, _ist_type, off_mid, off_high, _reserved = struct.unpack("<HHHHII", raw[:16])
        addr = off_low | (off_mid << 16) | (off_high << 32)
        return selector, addr
    off_low, selector, _access, off_high = struct.unpack("<HHHH", raw[:8])
    addr = off_low | (off_high << 16)
    return selector, addr


class Idt(interfaces.plugins.PluginInterface):
    """Displays Windows Interrupt Descriptor Table (IDT) entries and flags unknown handlers."""

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
            requirements.BooleanRequirement(
                name="hooked-only",
                description="Show only IDT entries whose handler falls outside known kernel modules",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="kpcrs", component=kpcrs.KPCRs, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
        ]

    @staticmethod
    def _resolve_module(addr: int, mod_ranges: List[Tuple[int, int, str]]) -> str:
        for base, end, name in mod_ranges:
            if base <= addr < end:
                return name
        return "UNKNOWN"

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]
        kernel_layer = self.context.layers[kernel.layer_name]
        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        hooked_only = self.config.get("hooked-only", False)

        # Collect loaded kernel module address ranges
        mod_ranges: List[Tuple[int, int, str]] = []
        for mod in modules.Modules.list_modules(self.context, kernel_name):
            try:
                base = int(mod.DllBase)
                size = int(mod.SizeOfImage)
                name = mod.BaseDllName.get_string()
                if base and size:
                    mod_ranges.append((base, base + size, name))
            except exceptions.InvalidAddressException:
                continue

        entry_size = 16 if is_64bit else 8

        for cpu_idx, item in enumerate(kpcrs.KPCRs.list_kpcrs(self.context, kernel_name)):
            kpcr = item[0] if isinstance(item, tuple) else item
            idt_base = 0
            for field in ("IdtBase", "IDT"):
                if kpcr.has_member(field):
                    try:
                        idt_base = int(getattr(kpcr, field))
                        if idt_base:
                            break
                    except exceptions.InvalidAddressException:
                        pass
            if not idt_base:
                continue

            try:
                idt_bytes = kernel_layer.read(idt_base, 256 * entry_size, pad=True)
            except exceptions.InvalidAddressException:
                continue

            for idx in range(256):
                chunk = idt_bytes[idx * entry_size : (idx + 1) * entry_size]
                if len(chunk) < entry_size:
                    break
                selector, handler_addr = decode_idt_entry(chunk, is_64bit)
                if not handler_addr:
                    continue

                mod_name = self._resolve_module(handler_addr, mod_ranges)
                status = "SUSPICIOUS (Unknown Module)" if mod_name == "UNKNOWN" else "OK"
                if hooked_only and mod_name != "UNKNOWN":
                    continue

                yield (
                    0,
                    (
                        cpu_idx,
                        format_hints.Hex(idx),
                        format_hints.Hex(selector),
                        format_hints.Hex(handler_addr),
                        mod_name,
                        status,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("CPU", int),
                ("Index", format_hints.Hex),
                ("Selector", format_hints.Hex),
                ("Handler Address", format_hints.Hex),
                ("Module", str),
                ("Status", str),
            ],
            self._generator(),
        )
