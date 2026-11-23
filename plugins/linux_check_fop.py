# Volatility 3 plugin: Linux CheckFop
# Checks file_operations / proc_ops function pointers on /proc entries and open files for rootkit hooks.

import logging
from typing import Iterable, List, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.framework.symbols.linux.utilities import modules as linux_modules
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

# High-value file_operations / proc_ops callbacks commonly targeted by LKM rootkits
FOP_MEMBERS = (
    "llseek",
    "read",
    "write",
    "read_iter",
    "write_iter",
    "iterate",
    "iterate_shared",
    "readdir",
    "poll",
    "unlocked_ioctl",
    "compat_ioctl",
    "mmap",
    "open",
    "flush",
    "release",
    "proc_open",
    "proc_read",
    "proc_read_iter",
    "proc_write",
    "proc_lseek",
    "proc_release",
    "proc_poll",
    "proc_ioctl",
    "proc_mmap",
)


class CheckFop(interfaces.plugins.PluginInterface):
    """Checks Linux file_operations and proc_ops pointers for rootkit hooks."""

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
            requirements.BooleanRequirement(
                name="all",
                description="Show all non-NULL callbacks, not only suspicious/unknown handlers",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="linux_modules", component=linux_modules.Modules, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    @staticmethod
    def _is_suspicious(module_name: str, symbol_name: str) -> bool:
        if not module_name or module_name == "UNKNOWN":
            return True
        if not symbol_name or symbol_name == "UNKNOWN":
            return True
        return False

    def _check_ops_struct(
        self,
        kernel,
        handlers,
        source: str,
        target_name: str,
        ops_obj,
        show_all: bool,
    ) -> Iterable[Tuple[int, Tuple]]:
        for member in FOP_MEMBERS:
            if not ops_obj.has_member(member):
                continue
            try:
                ptr = int(ops_obj.member(attr=member))
            except (TypeError, ValueError, exceptions.InvalidAddressException):
                continue
            if not ptr:
                continue

            mod_name, sym_name = linux_modules.Modules.lookup_module_address(
                self.context, self.config["kernel"], handlers, ptr
            )
            mod_name = mod_name or "UNKNOWN"
            sym_name = sym_name or "UNKNOWN"

            if not show_all and not self._is_suspicious(mod_name, sym_name):
                continue

            yield (
                0,
                (
                    source,
                    target_name,
                    member,
                    format_hints.Hex(ptr),
                    mod_name,
                    sym_name,
                ),
            )

    def _walk_proc_dir(
        self,
        kernel,
        handlers,
        pde,
        prefix: str,
        seen_pdes: Set[int],
        seen_ops: Set[int],
        show_all: bool,
        depth: int = 0,
    ) -> Iterable[Tuple[int, Tuple]]:
        if depth > 16:
            return

        pde_addr = int(pde.vol.offset)
        if pde_addr in seen_pdes:
            return
        seen_pdes.add(pde_addr)

        name = ""
        if pde.has_member("name"):
            try:
                name_obj = pde.name
                if hasattr(name_obj, "dereference"):
                    name = utility.pointer_to_string(name_obj, count=256)
                else:
                    name = utility.array_to_string(name_obj)
            except (ValueError, TypeError, exceptions.InvalidAddressException):
                name = ""
        full_name = f"{prefix}/{name}".replace("//", "/") if name else prefix

        # Kernel < 5.6: proc_fops (file_operations *); Kernel >= 5.6: proc_ops (proc_ops *)
        for field in ("proc_ops", "proc_fops"):
            if pde.has_member(field):
                try:
                    ops_ptr = int(getattr(pde, field))
                    if ops_ptr and ops_ptr not in seen_ops:
                        seen_ops.add(ops_ptr)
                        ops_obj = getattr(pde, field).dereference()
                        yield from self._check_ops_struct(
                            kernel, handlers, "procfs", full_name, ops_obj, show_all
                        )
                except exceptions.InvalidAddressException:
                    pass

        # Traverse children via subdir (older linked list) or subdir_node (rb_tree)
        if pde.has_member("subdir"):
            try:
                child_ptr = int(pde.subdir)
                guard = 0
                while child_ptr and child_ptr not in seen_pdes and guard < 2048:
                    guard += 1
                    child = kernel.object(
                        object_type="proc_dir_entry",
                        offset=child_ptr,
                        absolute=True,
                    )
                    yield from self._walk_proc_dir(
                        kernel, handlers, child, full_name, seen_pdes, seen_ops, show_all, depth + 1
                    )
                    child_ptr = int(child.next) if child.has_member("next") else 0
            except exceptions.InvalidAddressException:
                pass

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        show_all = self.config.get("all", False)

        mods = linux_modules.Modules.list_modules(self.context, self.config["kernel"])
        handlers = linux_modules.Modules.mask_mods_list(
            self.context, kernel.layer_name, mods
        )
        # Include core kernel text range (_text .. _etext) so built-in kernel handlers resolve properly
        try:
            k_start = kernel.object_from_symbol("_text").vol.offset
            k_end = kernel.object_from_symbol("_etext").vol.offset
            if k_start and k_end and k_end > k_start:
                handlers.insert(0, ("kernel", k_start, k_end))
        except Exception:
            pass

        seen_ops: Set[int] = set()

        # 1. Check /proc root and proc_dir_entry tree
        if kernel.has_symbol("proc_root"):
            try:
                proc_root = kernel.object_from_symbol("proc_root")
                yield from self._walk_proc_dir(
                    kernel, handlers, proc_root, "/proc", set(), seen_ops, show_all
                )
            except exceptions.InvalidAddressException as excp:
                vollog.debug(f"Unable to walk proc_root: {excp}")

        # 2. Check file_operations of open file descriptors across running processes
        for task in pslist.PsList.list_tasks(
            context=self.context, vmlinux_module_name=self.config["kernel"]
        ):
            try:
                pid = int(task.pid)
                comm = utility.array_to_string(task.comm)
            except exceptions.InvalidAddressException:
                continue

            try:
                for fd_num, filp, full_path in linux.LinuxUtilities.files_descriptors_for_process(
                    self.context, kernel.symbol_table_name, task
                ):
                    try:
                        f_op_ptr = int(filp.f_op)
                        if not f_op_ptr or f_op_ptr in seen_ops:
                            continue
                        seen_ops.add(f_op_ptr)
                        f_op = filp.f_op.dereference()
                        label = f"{comm}({pid}) fd={fd_num} {full_path}"
                        yield from self._check_ops_struct(
                            kernel, handlers, "open_file", label, f_op, show_all
                        )
                    except exceptions.InvalidAddressException:
                        continue
            except exceptions.InvalidAddressException:
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Source", str),
                ("Target", str),
                ("Member", str),
                ("Handler Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
