# Volatility 3 plugin: Linux PltHook
# Inspects ELF64 .got.plt relocation entries in running processes to detect userland GOT/PLT hooks.

import logging
import struct
from typing import Dict, Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

PT_DYNAMIC = 2
DT_NULL = 0
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_JMPREL = 23


def parse_elf64_dynamic_info(elf_hdr: bytes, read_fn, base_addr: int) -> Optional[Dict[int, int]]:
    """Parses ELF64 program headers to extract PT_DYNAMIC tags (DT_JMPREL, DT_PLTRELSZ, DT_SYMTAB, DT_STRTAB)."""
    if len(elf_hdr) < 64 or elf_hdr[:4] != b"\x7fELF" or elf_hdr[4] != 2:
        return None
    e_type = struct.unpack_from("<H", elf_hdr, 16)[0]
    e_phoff = struct.unpack_from("<Q", elf_hdr, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", elf_hdr, 54)
    if e_phentsize < 56 or e_phnum == 0 or e_phnum > 64:
        return None

    # ET_DYN (3) uses load bias = base_addr; ET_EXEC (2) uses absolute vaddrs (bias = 0)
    load_bias = base_addr if e_type == 3 else 0

    ph_bytes = read_fn(base_addr + e_phoff, e_phentsize * e_phnum)
    if not ph_bytes or len(ph_bytes) < e_phentsize * e_phnum:
        return None

    dyn_vaddr = dyn_size = 0
    for i in range(e_phnum):
        p_type, _p_flags, _p_off, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
            "<IIQQQQQQ", ph_bytes, i * e_phentsize
        )
        if p_type == PT_DYNAMIC:
            dyn_vaddr = load_bias + p_vaddr
            dyn_size = min(p_memsz or p_filesz, 65536)
            break

    if not dyn_vaddr or dyn_size < 16:
        return None

    dyn_bytes = read_fn(dyn_vaddr, dyn_size)
    if not dyn_bytes:
        return None

    tags: Dict[int, int] = {"bias": load_bias}
    for off in range(0, len(dyn_bytes) - 15, 16):
        d_tag, d_val = struct.unpack_from("<qQ", dyn_bytes, off)
        if d_tag == DT_NULL:
            break
        if d_tag in (DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_JMPREL):
            tags[d_tag] = d_val
    return tags


class PltHook(interfaces.plugins.PluginInterface):
    """Detects Linux userland GOT/PLT hooks in ELF64 process mappings."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="all",
                description="Show all resolved PLT/GOT entries, not only suspicious hooks",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    @staticmethod
    def _resolve_vma(addr: int, vmas: List[Tuple[int, int, str]]) -> str:
        for start, end, path in vmas:
            if start <= addr < end:
                return path or "<anonymous>"
        return "<unmapped>"

    @staticmethod
    def _read_cstr(read_fn, addr: int, max_len: int = 128) -> str:
        raw = read_fn(addr, max_len)
        if not raw:
            return ""
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    def _generator(self, tasks) -> Iterable[Tuple[int, Tuple]]:
        show_all = self.config.get("all", False)

        for task in tasks:
            try:
                pid = int(task.pid)
                comm = utility.array_to_string(task.comm)
                proc_layer_name = task.add_process_layer()
                if not proc_layer_name:
                    continue
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException:
                continue

            # Collect process VMA map for target resolution
            vma_ranges: List[Tuple[int, int, str]] = []
            elf_bases: List[Tuple[int, int, str]] = []
            seen_paths = set()
            try:
                for vma in task.mm.get_vma_iter():
                    start = int(vma.vm_start)
                    end = int(vma.vm_end)
                    path = vma.get_name(self.context, task) or ""
                    vma_ranges.append((start, end, path))
                    if path and path not in seen_paths and not path.startswith("["):
                        seen_paths.add(path)
                        elf_bases.append((start, end, path))
            except (AttributeError, exceptions.InvalidAddressException):
                continue

            def read_mem(addr: int, size: int) -> Optional[bytes]:
                try:
                    return proc_layer.read(addr, size, pad=False)
                except exceptions.InvalidAddressException:
                    return None

            for mod_start, mod_end, mod_path in elf_bases:
                hdr = read_mem(mod_start, 64)
                if not hdr:
                    continue
                tags = parse_elf64_dynamic_info(hdr, read_mem, mod_start)
                if not tags or not all(k in tags for k in (DT_JMPREL, DT_PLTRELSZ, DT_SYMTAB, DT_STRTAB)):
                    continue

                bias = tags["bias"]
                jmprel = tags[DT_JMPREL]
                pltrelsz = min(tags[DT_PLTRELSZ], 65536)
                symtab = tags[DT_SYMTAB]
                strtab = tags[DT_STRTAB]

                rela_bytes = read_mem(jmprel, pltrelsz)
                if not rela_bytes:
                    continue

                # Elf64_Rela entry is 24 bytes: r_offset (8), r_info (8), r_addend (8)
                for off in range(0, len(rela_bytes) - 23, 24):
                    r_offset, r_info, _r_addend = struct.unpack_from("<QQq", rela_bytes, off)
                    got_addr = bias + r_offset
                    got_raw = read_mem(got_addr, 8)
                    if not got_raw:
                        continue
                    target_addr = struct.unpack("<Q", got_raw)[0]
                    if not target_addr:
                        continue

                    # Unresolved lazy PLT stub points back into the binary itself
                    if mod_start <= target_addr < mod_end:
                        continue

                    target_map = self._resolve_vma(target_addr, vma_ranges)
                    suspicious = target_map in ("<anonymous>", "<unmapped>") or target_map.startswith("/tmp/") or target_map.startswith("/dev/shm/") or "(deleted)" in target_map

                    if not show_all and not suspicious:
                        continue

                    sym_idx = r_info >> 32
                    sym_raw = read_mem(symtab + sym_idx * 24, 24)
                    sym_name = f"sym_{sym_idx}"
                    if sym_raw:
                        st_name = struct.unpack_from("<I", sym_raw, 0)[0]
                        resolved = self._read_cstr(read_mem, strtab + st_name)
                        if resolved:
                            sym_name = resolved

                    status = "SUSPICIOUS" if suspicious else "OK"
                    yield (
                        0,
                        (
                            pid,
                            comm,
                            mod_path,
                            sym_name,
                            format_hints.Hex(got_addr),
                            format_hints.Hex(target_addr),
                            target_map,
                            status,
                        ),
                    )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_processes(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=filter_func,
        )
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Binary", str),
                ("Symbol", str),
                ("GOT Address", format_hints.Hex),
                ("Target Address", format_hints.Hex),
                ("Target Mapping", str),
                ("Status", str),
            ],
            self._generator(tasks),
        )
