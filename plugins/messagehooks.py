# Volatility 3 plugin: Windows MessageHooks
# Enumerates Windows desktop message hooks (SetWindowsHookEx / tagHOOK) for keylogger and DLL injection detection.

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)

# WH_* hook types indexed from -1 (WH_MSGFILTER) to 14 (WH_MOUSE_LL) -> aphkStart[0..15]
HOOK_TYPES = [
    "WH_MSGFILTER",
    "WH_JOURNALRECORD",
    "WH_JOURNALPLAYBACK",
    "WH_KEYBOARD",
    "WH_GETMESSAGE",
    "WH_CALLWNDPROC",
    "WH_CBT",
    "WH_SYSMSGFILTER",
    "WH_MOUSE",
    "WH_HARDWARE",
    "WH_DEBUG",
    "WH_SHELL",
    "WH_FOREGROUNDIDLE",
    "WH_CALLWNDPROCRET",
    "WH_KEYBOARD_LL",
    "WH_MOUSE_LL",
]

HOOK_FLAGS = (
    (0x0001, "HF_GLOBAL"),
    (0x0002, "HF_ANSI"),
    (0x0004, "HF_NEEDHC_SKIP"),
    (0x0008, "HF_HUNG"),
    (0x0010, "HF_HOOKFAULTED"),
    (0x0020, "HF_NOPLAYBACKDELAY"),
    (0x0040, "HF_WX86KNOWNDLL"),
    (0x0080, "HF_DESTROYED"),
    (0x0100, "HF_INCHECKWHF"),
)


def _decode_hook_flags(flags: int) -> str:
    names = [name for bit, name in HOOK_FLAGS if flags & bit]
    return "|".join(names) if names else f"0x{flags:x}"


class MessageHooks(interfaces.plugins.PluginInterface):
    """Lists Windows desktop message hooks (SetWindowsHookEx) from tagDESKTOP structures."""

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
            requirements.VersionRequirement(
                name="windowstations",
                component=windowstations.WindowStations,
                version=(1, 0, 0),
            ),
        ]

    @staticmethod
    def _extract_process_info(hook) -> Tuple[str, int]:
        try:
            proc = hook.head.pti.ppi.Process.dereference()
            name = utility.array_to_string(proc.ImageFileName) or "unknown"
            pid = int(proc.UniqueProcessId)
            return name, pid
        except (AttributeError, exceptions.InvalidAddressException):
            return "unknown", 0

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]

        try:
            stations = list(
                windowstations.WindowStations.scan_window_stations(
                    self.context, self.config_path, kernel_name
                )
            )
        except NotImplementedError as excp:
            vollog.warning(f"MessageHooks requires x64 Windows GUI symbols: {excp}")
            return

        for winsta, station_name, session_id in stations:
            for desktop, desktop_name in winsta.desktops(kernel.symbol_table_name):
                try:
                    desk_info = desktop.pDeskInfo.dereference()
                except (AttributeError, exceptions.InvalidAddressException):
                    continue

                if not desk_info.has_member("aphkStart"):
                    continue

                try:
                    aphk_start = desk_info.aphkStart
                except exceptions.InvalidAddressException:
                    continue

                for idx, hook_type_name in enumerate(HOOK_TYPES):
                    if idx >= len(aphk_start):
                        break
                    try:
                        hook_ptr = aphk_start[idx]
                    except (IndexError, exceptions.InvalidAddressException):
                        continue

                    seen = set()
                    guard = 0
                    while hook_ptr and int(hook_ptr) and int(hook_ptr) not in seen and guard < 256:
                        addr = int(hook_ptr)
                        seen.add(addr)
                        guard += 1
                        try:
                            hook = hook_ptr.dereference()
                        except exceptions.InvalidAddressException:
                            break

                        flags_str = "-"
                        off_pfn = 0
                        ihmod = -1
                        try:
                            if hook.has_member("flags"):
                                flags_str = _decode_hook_flags(int(hook.flags))
                            if hook.has_member("offPfn"):
                                off_pfn = int(hook.offPfn)
                            if hook.has_member("ihmod"):
                                ihmod = int(hook.ihmod)
                        except exceptions.InvalidAddressException:
                            pass

                        proc_name, pid = self._extract_process_info(hook)
                        yield (
                            0,
                            (
                                int(session_id) if session_id is not None else -1,
                                str(station_name),
                                str(desktop_name),
                                format_hints.Hex(addr),
                                hook_type_name,
                                flags_str,
                                format_hints.Hex(off_pfn),
                                ihmod,
                                proc_name,
                                pid,
                            ),
                        )

                        try:
                            hook_ptr = hook.phkNext if hook.has_member("phkNext") else None
                        except exceptions.InvalidAddressException:
                            break

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", int),
                ("WindowStation", str),
                ("Desktop", str),
                ("Hook Offset", format_hints.Hex),
                ("Hook Type", str),
                ("Flags", str),
                ("Function Offset", format_hints.Hex),
                ("Module Index", int),
                ("Process", str),
                ("PID", int),
            ],
            self._generator(),
        )
