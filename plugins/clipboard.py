# Volatility 3 plugin: Windows Clipboard
# Extracts clipboard metadata and text content from tagWINDOWSTATION clipboard chains.

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import windowstations

vollog = logging.getLogger(__name__)

CLIPBOARD_FORMATS = {
    1: "CF_TEXT",
    2: "CF_BITMAP",
    3: "CF_METAFILEPICT",
    4: "CF_SYLK",
    5: "CF_DIF",
    6: "CF_TIFF",
    7: "CF_OEMTEXT",
    8: "CF_DIB",
    9: "CF_PALETTE",
    10: "CF_PENDATA",
    11: "CF_RIFF",
    12: "CF_WAVE",
    13: "CF_UNICODETEXT",
    14: "CF_ENHMETAFILE",
    15: "CF_HDROP",
    16: "CF_LOCALE",
    17: "CF_DIBV5",
}


def _format_name(fmt: int) -> str:
    return CLIPBOARD_FORMATS.get(fmt, f"0x{fmt:x}")


def _decode_clip_bytes(fmt: int, raw: bytes) -> str:
    if not raw:
        return ""
    if fmt == 13:  # CF_UNICODETEXT
        text = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        return text[:512]
    if fmt in (1, 7):  # CF_TEXT / CF_OEMTEXT
        text = raw.decode("latin-1", errors="replace").split("\x00", 1)[0]
        return text[:512]
    return raw[:32].hex()


class Clipboard(interfaces.plugins.PluginInterface):
    """Extracts Windows clipboard entries and text data from WindowStations."""

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
            vollog.warning(f"Clipboard requires x64 Windows GUI symbols: {excp}")
            return

        for winsta, station_name, session_id in stations:
            if not (winsta.has_member("pClipBase") and winsta.has_member("cNumClipFormats")):
                continue

            try:
                num_formats = int(winsta.cNumClipFormats)
                clip_base_ptr = int(winsta.pClipBase)
            except exceptions.InvalidAddressException:
                continue

            if not clip_base_ptr or num_formats <= 0 or num_formats > 256:
                continue

            layer = self.context.layers[winsta.vol.layer_name]
            clip_type = None
            for type_name in ("tagCLIP", "_tagCLIP"):
                try:
                    clip_type = kernel.get_type(type_name)
                    break
                except exceptions.SymbolError:
                    continue

            # Fallback entry size (fmt:4 + pad:4 + hData:8 + fGlobalHandle:4 + pad:4 = 24 on x64, 12 on x86)
            entry_size = clip_type.size if clip_type is not None else 24

            for idx in range(num_formats):
                entry_off = clip_base_ptr + idx * entry_size
                fmt = 0
                handle = 0
                if clip_type is not None:
                    try:
                        clip = kernel.object(
                            object_type=clip_type.vol.type_name.split("!")[-1],
                            layer_name=winsta.vol.layer_name,
                            offset=entry_off,
                            absolute=True,
                        )
                        fmt = int(clip.fmt)
                        handle = int(clip.hData)
                    except exceptions.InvalidAddressException:
                        continue
                else:
                    try:
                        raw_entry = layer.read(entry_off, entry_size, pad=False)
                        fmt = int.from_bytes(raw_entry[0:4], "little")
                        handle = int.from_bytes(
                            raw_entry[8:16] if entry_size >= 16 else raw_entry[4:8], "little"
                        )
                    except exceptions.InvalidAddressException:
                        continue

                data_preview = "-"
                data_size = 0
                obj_addr = 0

                # Try reading tagCLIPDATA if hData points directly to a readable kernel/session object
                if handle > 0x10000:
                    try:
                        for cd_type in ("tagCLIPDATA", "_tagCLIPDATA"):
                            try:
                                cd = kernel.object(
                                    object_type=cd_type,
                                    layer_name=winsta.vol.layer_name,
                                    offset=handle,
                                    absolute=True,
                                )
                                cb = int(cd.cbData)
                                if 0 < cb <= 65536 and cd.has_member("abData"):
                                    raw_data = layer.read(cd.abData.vol.offset, min(cb, 2048), pad=False)
                                    data_size = cb
                                    obj_addr = handle
                                    data_preview = _decode_clip_bytes(fmt, raw_data)
                                break
                            except exceptions.SymbolError:
                                continue
                    except exceptions.InvalidAddressException:
                        pass

                yield (
                    0,
                    (
                        int(session_id) if session_id is not None else -1,
                        str(station_name),
                        _format_name(fmt),
                        format_hints.Hex(handle),
                        format_hints.Hex(obj_addr),
                        data_size,
                        data_preview,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", int),
                ("WindowStation", str),
                ("Format", str),
                ("Handle", format_hints.Hex),
                ("Object", format_hints.Hex),
                ("Size", int),
                ("Data", str),
            ],
            self._generator(),
        )
