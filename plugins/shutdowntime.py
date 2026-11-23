# Volatility 3 plugin: Windows ShutdownTime
# Reads ControlSet00X\Control\Windows\ShutdownTime from the SYSTEM registry hive in memory.

import datetime
import logging
import struct
from typing import Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class ShutdownTime(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Extracts the last system shutdown timestamp from the SYSTEM registry hive."""

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
            requirements.IntRequirement(
                name="offset",
                description="SYSTEM Hive Offset",
                default=None,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="hivelist", component=hivelist.HiveList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
        ]

    @staticmethod
    def _get_current_controlset(hive) -> str:
        try:
            select_key = hive.get_key("Select")
            for val in select_key.get_values():
                if val.get_name().lower() == "current":
                    current = val.decode_data()
                    if isinstance(current, bytes) and len(current) >= 4:
                        current = struct.unpack("<I", current[:4])[0]
                    if isinstance(current, int):
                        return f"ControlSet{current:03d}"
        except (KeyError, exceptions.InvalidAddressException, exceptions.RegistryException) as excp:
            vollog.debug(f"Unable to read Select\\Current: {excp}")
        return "ControlSet001"

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        hive_offsets = [self.config["offset"]] if self.config.get("offset") is not None else None
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            filter_string="system" if hive_offsets is None else None,
            hive_offsets=hive_offsets,
        ):
            hive_name = hive.get_name() or ""
            if hive_offsets is None and not hive_name.lower().endswith("\\system"):
                continue

            control_set = self._get_current_controlset(hive)
            key_path = f"{control_set}\\Control\\Windows"
            try:
                win_key = hive.get_key(key_path)
            except (KeyError, exceptions.InvalidAddressException, exceptions.RegistryException) as excp:
                vollog.debug(f"Could not open {key_path} in {hive_name}: {excp}")
                continue

            for val in win_key.get_values():
                if val.get_name().lower() != "shutdowntime":
                    continue
                raw = val.decode_data()
                if isinstance(raw, bytes) and len(raw) >= 8:
                    filetime = struct.unpack("<Q", raw[:8])[0]
                    dt = conversion.wintime_to_datetime(filetime)
                else:
                    dt = renderers.UnparsableValue()

                yield (
                    0,
                    (
                        format_hints.Hex(hive.hive_offset),
                        hive_name,
                        control_set,
                        dt,
                    ),
                )

    def generate_timeline(self):
        for _, row in self._generator():
            _, hive_name, control_set, dt = row
            if isinstance(dt, datetime.datetime):
                yield (f"ShutdownTime: {hive_name} ({control_set})", timeliner.TimeLinerType.MODIFIED, dt)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Hive Offset", format_hints.Hex),
                ("Registry", str),
                ("ControlSet", str),
                ("ShutdownTime", datetime.datetime),
            ],
            self._generator(),
        )
