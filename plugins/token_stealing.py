# Volatility 3 plugin: Windows TokenStealing
# Detects kernel token stealing / privilege escalation by inspecting _EPROCESS.Token pointers.

import logging
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

# Common user-mode parent processes that should not spawn processes sharing PID 4's SYSTEM token
SUSPICIOUS_PARENTS = {
    "explorer.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "winword.exe",
    "excel.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
}

# System processes that legitimately share or hold the initial SYSTEM token
EXPECTED_SYSTEM_PROCS = {
    "system",
    "registry",
    "smss.exe",
    "memcompression",
    "secure system",
    "vmmem",
}


class TokenStealing(interfaces.plugins.PluginInterface):
    """Detects Windows kernel token stealing by finding processes sharing identical _TOKEN objects."""

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
                name="all",
                description="Show all processes with their _TOKEN address (not only suspicious ones)",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
        ]

    @staticmethod
    def _extract_token_addr(proc, is_64bit: bool) -> int:
        # _EX_FAST_REF masks out the low RefCnt bits (4 bits on x64, 3 bits on x86)
        mask = ~0xF if is_64bit else ~0x7
        try:
            raw_val = int(proc.Token.Value)
            return raw_val & mask
        except (AttributeError, exceptions.InvalidAddressException):
            try:
                tok = proc.Token.dereference()
                return int(tok.vol.offset) & mask
            except exceptions.InvalidAddressException:
                return 0

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        show_all = self.config.get("all", False)

        procs: List[Dict] = []
        by_pid: Dict[int, str] = {}
        by_token: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
        system_token_addr = 0

        for proc in pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"]
        ):
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue

            token_addr = self._extract_token_addr(proc, is_64bit)
            by_pid[pid] = name
            if token_addr:
                by_token[token_addr].append((pid, name))
            if pid == 4 or name.lower() == "system":
                if token_addr:
                    system_token_addr = token_addr

            procs.append(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "token": token_addr,
                }
            )

        for info in procs:
            pid = info["pid"]
            ppid = info["ppid"]
            name = info["name"]
            parent_name = by_pid.get(ppid, "<exited>")
            token_addr = info["token"]

            peers = [(p, n) for (p, n) in by_token.get(token_addr, []) if p != pid]
            reasons: List[str] = []

            if token_addr and system_token_addr and token_addr == system_token_addr:
                if name.lower() not in EXPECTED_SYSTEM_PROCS:
                    reasons.append("Shares PID 4 SYSTEM _TOKEN")
            if peers and name.lower() not in EXPECTED_SYSTEM_PROCS:
                reasons.append(f"Shared _TOKEN with {len(peers)} other process(es)")
            if (
                token_addr
                and system_token_addr
                and token_addr == system_token_addr
                and parent_name.lower() in SUSPICIOUS_PARENTS
            ):
                reasons.append(f"User-mode parent ({parent_name}) with SYSTEM _TOKEN")

            if not reasons and not show_all:
                continue

            shared_str = ", ".join(f"{n}({p})" for p, n in peers[:6])
            if len(peers) > 6:
                shared_str += f", +{len(peers) - 6} more"

            yield (
                0,
                (
                    pid,
                    ppid,
                    name,
                    parent_name,
                    format_hints.Hex(token_addr),
                    shared_str or "-",
                    "; ".join(reasons) if reasons else "Normal",
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("PPID", int),
                ("Process", str),
                ("Parent", str),
                ("Token Address", format_hints.Hex),
                ("Shared With", str),
                ("Assessment", str),
            ],
            self._generator(),
        )
