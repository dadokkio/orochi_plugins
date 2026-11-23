# Volatility 3 plugin: Windows UsnJrnl
# Carves and parses NTFS USN_RECORD_V2 structures from physical memory (zero kernel-symbol fragility).

import datetime
import logging
import struct
from typing import Iterable, List, Optional, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import conversion, format_hints
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)

# Valid FILETIME bounds: 2000-01-01 .. 2040-01-01
MIN_FILETIME = 125911584000000000
MAX_FILETIME = 138534624000000000

INVALID_NTFS_CHARS = set('<>:"/\\|?*')

USN_REASONS = (
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x80000000, "CLOSE"),
)
VALID_REASON_MASK = sum(bit for bit, _ in USN_REASONS) | 0x00C00000

FILE_ATTRIBUTES = (
    (0x0001, "READONLY"),
    (0x0002, "HIDDEN"),
    (0x0004, "SYSTEM"),
    (0x0010, "DIRECTORY"),
    (0x0020, "ARCHIVE"),
    (0x0080, "NORMAL"),
    (0x0100, "TEMPORARY"),
    (0x0400, "REPARSE_POINT"),
    (0x0800, "COMPRESSED"),
    (0x4000, "ENCRYPTED"),
)

# Signature for MajorVersion=2, MinorVersion=0 (+4) and FileNameOffset=60 (+58 -> 50 bytes between)
USN_V2_REGEX = rb"\x02\x00\x00\x00.{50}\x3c\x00"


def _decode_flags(val: int, table: Tuple[Tuple[int, str], ...]) -> str:
    names = [name for bit, name in table if val & bit]
    return "|".join(names) if names else f"0x{val:x}"


def parse_usn_v2_record(buf: bytes) -> Optional[Tuple[int, datetime.datetime, str, int, int, str, str]]:
    """Validates and parses a USN_RECORD_V2 byte buffer.

    Returns (usn, timestamp, filename, mft_ref, parent_mft_ref, reason_str, attr_str) or None.
    """
    if len(buf) < 64:
        return None

    (
        rec_len,
        major,
        minor,
        file_ref,
        parent_ref,
        usn,
        timestamp,
        reason,
        _source_info,
        _security_id,
        file_attrs,
        fname_len,
        fname_off,
    ) = struct.unpack_from("<IHHQQQQIIIIHH", buf, 0)

    if major != 2 or minor != 0:
        return None
    if rec_len < 64 or rec_len > 600 or (rec_len % 8) != 0:
        return None
    if fname_off != 60 or fname_len < 2 or fname_len > 510 or (fname_len % 2) != 0:
        return None
    if 60 + fname_len > rec_len or 60 + fname_len > len(buf):
        return None
    if not (MIN_FILETIME <= timestamp <= MAX_FILETIME):
        return None
    if reason == 0 or (reason & ~VALID_REASON_MASK) != 0:
        return None
    if file_attrs == 0 or file_attrs > 0x0007FFFF:
        return None

    try:
        filename = buf[60 : 60 + fname_len].decode("utf-16-le")
    except UnicodeDecodeError:
        return None

    if not filename or any(ord(c) < 0x20 or c in INVALID_NTFS_CHARS for c in filename):
        return None

    dt = conversion.wintime_to_datetime(timestamp)
    if not isinstance(dt, datetime.datetime):
        return None

    # Lower 48 bits of NTFS file reference number are the MFT record index
    mft_ref = file_ref & 0x0000FFFFFFFFFFFF
    parent_mft_ref = parent_ref & 0x0000FFFFFFFFFFFF

    return (
        usn,
        dt,
        filename,
        mft_ref,
        parent_mft_ref,
        _decode_flags(reason, USN_REASONS),
        _decode_flags(file_attrs, FILE_ATTRIBUTES),
    )


class UsnJrnl(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans memory for NTFS USN_RECORD_V2 journal entries."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
        ]

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        primary = self.context.layers[self.config["primary"]]
        phys_layer_name = primary.config.get("memory_layer", self.config["primary"])
        layer = self.context.layers[phys_layer_name]

        seen = set()
        for match_off in layer.scan(self.context, scanners.RegExScanner(USN_V2_REGEX)):
            rec_off = match_off - 4
            if rec_off < 0 or (rec_off % 8) != 0:
                continue
            try:
                buf = layer.read(rec_off, 600, pad=True)
            except Exception:
                continue

            parsed = parse_usn_v2_record(buf)
            if parsed is None:
                continue

            usn, dt, filename, mft_ref, parent_mft_ref, reason_str, attr_str = parsed
            dedup_key = (usn, mft_ref, filename, reason_str)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            yield (
                0,
                (
                    format_hints.Hex(rec_off),
                    usn,
                    dt,
                    filename,
                    mft_ref,
                    parent_mft_ref,
                    reason_str,
                    attr_str,
                ),
            )

    def generate_timeline(self):
        for _, row in self._generator():
            _, usn, dt, filename, mft_ref, _, reason_str, _ = row
            if isinstance(dt, datetime.datetime):
                yield (
                    f"UsnJrnl: {filename} (MFT {mft_ref}, USN {usn}) [{reason_str}]",
                    timeliner.TimeLinerType.MODIFIED,
                    dt,
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("USN", int),
                ("Timestamp", datetime.datetime),
                ("FileName", str),
                ("MFT Ref", int),
                ("Parent MFT Ref", int),
                ("Reason", str),
                ("Attributes", str),
            ],
            self._generator(),
        )
