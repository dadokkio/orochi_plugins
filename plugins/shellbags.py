# Volatility 3 plugin: Windows ShellBags
# Parses BagMRU Shell Items from UsrClass.dat and NTUSER.DAT registry hives in memory.

import datetime
import logging
import struct
import uuid
from typing import Iterable, List, Optional, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)

KNOWN_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel (Category)",
    "5399e694-6ce5-4d6c-8fce-1d8870fdcba0": "Control Panel (All)",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users Files",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
}

BAGMRU_PATHS = (
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
)


def _dos_datetime(dos_date: int, dos_time: int) -> Optional[datetime.datetime]:
    if dos_date == 0 and dos_time == 0:
        return None
    day = dos_date & 0x1F
    month = (dos_date >> 5) & 0x0F
    year = ((dos_date >> 9) & 0x7F) + 1980
    sec = (dos_time & 0x1F) * 2
    minute = (dos_time >> 5) & 0x3F
    hour = (dos_time >> 11) & 0x1F
    try:
        return datetime.datetime(year, month, day, hour, minute, min(sec, 59), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _read_cstr(data: bytes, offset: int) -> Tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end == -1:
        return data[offset:].decode("latin-1", errors="replace"), len(data)
    return data[offset:end].decode("latin-1", errors="replace"), end + 1


def _read_utf16z(data: bytes, offset: int) -> str:
    chars = []
    pos = offset
    while pos + 2 <= len(data):
        ch = data[pos : pos + 2]
        if ch == b"\x00\x00":
            break
        chars.append(ch)
        pos += 2
    return b"".join(chars).decode("utf-16-le", errors="replace")


def _parse_beef0004(data: bytes) -> Tuple[Optional[str], Optional[datetime.datetime], Optional[datetime.datetime]]:
    """Parses the 0xBEEF0004 File Entry extension block for long Unicode name + created/accessed timestamps."""
    sig_pos = data.find(b"\x04\x00\xef\xbe")
    if sig_pos < 4 or sig_pos + 16 > len(data):
        return None, None, None
    ext_start = sig_pos - 4
    ext_size, ext_ver = struct.unpack_from("<HH", data, ext_start)
    if ext_size < 16 or ext_start + ext_size > len(data):
        ext_end = len(data)
    else:
        ext_end = ext_start + ext_size

    created = accessed = None
    if ext_start + 16 <= ext_end:
        c_date, c_time, a_date, a_time = struct.unpack_from("<HHHH", data, ext_start + 8)
        created = _dos_datetime(c_date, c_time)
        accessed = _dos_datetime(a_date, a_time)

    # Locate the primary Unicode name according to extension version
    name_off = None
    if ext_ver >= 0x09 and ext_start + 46 <= ext_end:
        name_off = ext_start + 46
    elif ext_ver >= 0x08 and ext_start + 42 <= ext_end:
        name_off = ext_start + 42
    elif ext_ver >= 0x07 and ext_start + 38 <= ext_end:
        name_off = ext_start + 38
    elif ext_ver >= 0x03 and ext_start + 20 <= ext_end:
        name_off = ext_start + 20

    long_name = _read_utf16z(data[:ext_end], name_off) if name_off is not None else None
    if long_name and all(c.isprintable() for c in long_name):
        return long_name, created, accessed
    return None, created, accessed


def _parse_shell_item(raw: bytes) -> Tuple[str, str, Optional[datetime.datetime], Optional[datetime.datetime], Optional[datetime.datetime]]:
    """Returns (item_type, display_name, modified, accessed, created)."""
    if not raw or len(raw) < 4:
        return "Unknown", "<empty>", None, None, None

    size = struct.unpack_from("<H", raw, 0)[0]
    item = raw[:size] if 4 <= size <= len(raw) else raw
    item_type = item[2]
    type_class = item_type & 0x70

    # Root folder (0x1F)
    if item_type == 0x1F and len(item) >= 20:
        guid = str(uuid.UUID(bytes_le=item[4:20]))
        label = KNOWN_GUIDS.get(guid.lower(), f"{{{guid}}}")
        return "RootFolder", label, None, None, None

    # Volume / Drive (0x20..0x2F)
    if type_class == 0x20:
        vol_name, _ = _read_cstr(item, 3)
        vol_name = vol_name.strip("\x00")
        if vol_name:
            return "Volume", vol_name, None, None, None
        return "Volume", "<volume>", None, None, None

    # File / Directory entry (0x30..0x3F)
    if type_class == 0x30 and len(item) >= 14:
        m_date, m_time = struct.unpack_from("<HH", item, 8)
        modified = _dos_datetime(m_date, m_time)
        short_name, _ = _read_cstr(item, 14)
        long_name, created, accessed = _parse_beef0004(item)
        name = long_name or short_name or "<unnamed>"
        kind = "Directory" if (item_type & 0x01) else "FileEntry"
        return kind, name, modified, accessed, created

    # Network location (0x40..0x4F)
    if type_class == 0x40 and len(item) >= 6:
        net_name, _ = _read_cstr(item, 5)
        return "Network", net_name or "<network>", None, None, None

    # URI (0x61)
    if item_type == 0x61 and len(item) >= 8:
        uri_str, _ = _read_cstr(item, 8)
        return "URI", uri_str or "<uri>", None, None, None

    # Fallback: try extracting printable UTF-16LE or ASCII
    long_name, created, accessed = _parse_beef0004(item)
    if long_name:
        return f"Other(0x{item_type:02x})", long_name, None, accessed, created
    return f"Other(0x{item_type:02x})", f"<0x{item_type:02x}>", None, None, None


class ShellBags(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Parses Windows ShellBags (BagMRU) from UsrClass.dat and NTUSER.DAT hives in memory."""

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
                description="Hive Offset",
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

    def _walk_bagmru(
        self,
        hive_name: str,
        key,
        reg_path: str,
        prefix_path: str,
        depth: int = 0,
    ) -> Iterable[Tuple[int, Tuple]]:
        if depth > 32:
            return

        try:
            last_write = conversion.wintime_to_datetime(key.LastWriteTime.QuadPart)
        except Exception:
            last_write = renderers.UnparsableValue()

        # Map numeric value names ("0", "1", ...) to parsed shell item tuples
        children = {}
        try:
            for val in key.get_values():
                vname = val.get_name()
                if not vname.isdigit():
                    continue
                raw = val.decode_data()
                if not isinstance(raw, bytes):
                    continue
                item_type, display_name, modified, accessed, created = _parse_shell_item(raw)
                full_path = f"{prefix_path}\\{display_name}" if prefix_path else display_name
                full_path = full_path.replace("\\\\", "\\") if not full_path.startswith("\\\\") else full_path
                children[vname] = full_path
                yield (
                    0,
                    (
                        hive_name,
                        f"{reg_path}\\{vname}",
                        last_write,
                        item_type,
                        full_path,
                        modified or renderers.NotApplicableValue(),
                        accessed or renderers.NotApplicableValue(),
                        created or renderers.NotApplicableValue(),
                    ),
                )
        except (exceptions.InvalidAddressException, exceptions.RegistryException) as excp:
            vollog.debug(f"Error enumerating values at {reg_path}: {excp}")

        # Recurse into matching subkeys ("0", "1", ...)
        try:
            for subkey in key.get_subkeys():
                sname = subkey.get_name()
                if not sname.isdigit():
                    continue
                child_prefix = children.get(sname, prefix_path)
                yield from self._walk_bagmru(
                    hive_name=hive_name,
                    key=subkey,
                    reg_path=f"{reg_path}\\{sname}",
                    prefix_path=child_prefix,
                    depth=depth + 1,
                )
        except (exceptions.InvalidAddressException, exceptions.RegistryException) as excp:
            vollog.debug(f"Error enumerating subkeys at {reg_path}: {excp}")

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        hive_offsets = [self.config["offset"]] if self.config.get("offset") is not None else None
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            kernel_module_name=self.config["kernel"],
            hive_offsets=hive_offsets,
        ):
            hive_name = hive.get_name() or ""
            lower_name = hive_name.lower()
            if hive_offsets is None and not (
                "usrclass.dat" in lower_name or "ntuser.dat" in lower_name
            ):
                continue

            for bag_path in BAGMRU_PATHS:
                try:
                    bag_key = hive.get_key(bag_path)
                except (KeyError, exceptions.InvalidAddressException, exceptions.RegistryException):
                    continue
                yield from self._walk_bagmru(
                    hive_name=hive_name,
                    key=bag_key,
                    reg_path=bag_path,
                    prefix_path="",
                )

    def generate_timeline(self):
        for _, row in self._generator():
            hive_name, _, last_write, _, full_path, modified, accessed, created = row
            if isinstance(last_write, datetime.datetime):
                yield (f"ShellBags (Key): {full_path} [{hive_name}]", timeliner.TimeLinerType.MODIFIED, last_write)
            if isinstance(modified, datetime.datetime):
                yield (f"ShellBags (Item): {full_path}", timeliner.TimeLinerType.MODIFIED, modified)
            if isinstance(accessed, datetime.datetime):
                yield (f"ShellBags (Item): {full_path}", timeliner.TimeLinerType.ACCESSED, accessed)
            if isinstance(created, datetime.datetime):
                yield (f"ShellBags (Item): {full_path}", timeliner.TimeLinerType.CREATED, created)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Hive", str),
                ("Registry Key", str),
                ("Last Write Time", datetime.datetime),
                ("Shell Item Type", str),
                ("Path", str),
                ("Modified", datetime.datetime),
                ("Accessed", datetime.datetime),
                ("Created", datetime.datetime),
            ],
            self._generator(),
        )
