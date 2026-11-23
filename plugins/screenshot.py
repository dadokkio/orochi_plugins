# Volatility 3 plugin: Windows Screenshot
# Generates wireframe PNG screenshots of Windows desktops from tagWND structures using Pillow.

import io
import logging
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from PIL import Image, ImageDraw

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import windows, windowstations

vollog = logging.getLogger(__name__)

WS_VISIBLE = 0x10000000
MAX_COORD = 16384
MAX_CANVAS_W = 7680
MAX_CANVAS_H = 4320


def _safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text or "unknown").strip("_") or "unknown"


def _extract_rect_and_visibility(window) -> Tuple[Optional[Tuple[int, int, int, int]], bool]:
    """Extracts (left, top, right, bottom) and WS_VISIBLE from tagWND (or subPointer on Win10 >= 17134)."""
    target = window
    try:
        if hasattr(window, "subPointer") and window.has_member("subPointer"):
            sub = window.subPointer
            if sub is not None and int(sub):
                target = sub.dereference()
    except exceptions.InvalidAddressException:
        target = window

    rect = None
    try:
        if target.has_member("rcWindow"):
            rc = target.rcWindow
            left, top, right, bottom = int(rc.left), int(rc.top), int(rc.right), int(rc.bottom)
            if (
                -MAX_COORD <= left < right <= MAX_COORD
                and -MAX_COORD <= top < bottom <= MAX_COORD
                and (right - left) <= MAX_CANVAS_W
                and (bottom - top) <= MAX_CANVAS_H
            ):
                rect = (left, top, right, bottom)
    except (AttributeError, exceptions.InvalidAddressException):
        rect = None

    visible = True
    try:
        if target.has_member("style"):
            visible = bool(int(target.style) & WS_VISIBLE)
    except (AttributeError, exceptions.InvalidAddressException):
        visible = True

    return rect, visible


def render_desktop_wireframe(
    win_entries: List[Tuple[Tuple[int, int, int, int], str, str, int]],
) -> Tuple[bytes, int, int]:
    """Renders a wireframe PNG image of desktop windows and returns (png_bytes, width, height)."""
    min_x = min(0, min(r[0] for r, _, _, _ in win_entries))
    min_y = min(0, min(r[1] for r, _, _, _ in win_entries))
    max_x = max(640, max(r[2] for r, _, _, _ in win_entries))
    max_y = max(480, max(r[3] for r, _, _, _ in win_entries))

    width = min(max(max_x - min_x, 640), MAX_CANVAS_W)
    height = min(max(max_y - min_y, 480), MAX_CANVAS_H)

    img = Image.new("RGB", (width, height), color=(30, 34, 42))
    draw = ImageDraw.Draw(img)

    for (left, top, right, bottom), title, proc_name, pid in win_entries:
        x0 = max(0, min(left - min_x, width - 1))
        y0 = max(0, min(top - min_y, height - 1))
        x1 = max(x0 + 1, min(right - min_x, width - 1))
        y1 = max(y0 + 1, min(bottom - min_y, height - 1))

        # Window body + border
        draw.rectangle([x0, y0, x1, y1], fill=(240, 242, 245), outline=(70, 90, 120), width=2)

        # Title bar (if tall enough)
        if y1 - y0 >= 22:
            bar_y1 = min(y0 + 20, y1)
            draw.rectangle([x0, y0, x1, bar_y1], fill=(52, 92, 148), outline=(70, 90, 120))
            label = f"{title} [{proc_name} ({pid})]" if title else f"{proc_name} ({pid})"
            max_chars = max(1, (x1 - x0 - 8) // 6)
            draw.text((x0 + 4, y0 + 4), label[:max_chars], fill=(255, 255, 255))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), width, height


class Screenshot(interfaces.plugins.PluginInterface):
    """Generates wireframe PNG screenshots of Windows desktops from tagWND structures."""

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
                name="all-windows",
                description="Include non-visible windows in the wireframe screenshot",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="windows", component=windows.Windows, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="windowstations",
                component=windowstations.WindowStations,
                version=(1, 0, 0),
            ),
        ]

    def _generator(self) -> Iterable[Tuple[int, Tuple]]:
        kernel_name = self.config["kernel"]
        include_hidden = self.config.get("all-windows", False)

        desktops_map: Dict[Tuple[int, str, str], List[Tuple[Tuple[int, int, int, int], str, str, int]]] = defaultdict(list)

        try:
            win_list = list(
                windows.Windows.list_windows(
                    self.context, self.config_path, kernel_name
                )
            )
        except NotImplementedError as excp:
            vollog.warning(f"Screenshot requires x64 Windows GUI symbols: {excp}")
            return

        for station_name, desktop_name, window, window_name in win_list:
            sess_id = window.get_session_id()
            if sess_id is None:
                continue

            rect, visible = _extract_rect_and_visibility(window)
            if rect is None:
                continue
            if not visible and not include_hidden:
                continue

            proc_name = "unknown"
            pid = 0
            process = window.get_process()
            if process is not None:
                try:
                    proc_name = utility.array_to_string(process.ImageFileName) or "unknown"
                    pid = int(process.UniqueProcessId)
                except exceptions.InvalidAddressException:
                    pass

            desktops_map[(int(sess_id), str(station_name), str(desktop_name))].append(
                (rect, window_name or "", proc_name, pid)
            )

        for (sess_id, station_name, desktop_name), win_entries in sorted(desktops_map.items()):
            png_bytes, width, height = render_desktop_wireframe(win_entries)
            filename = (
                f"session_{sess_id}.{_safe_filename(station_name)}.{_safe_filename(desktop_name)}.png"
            )
            status = filename
            try:
                with self.open(filename) as file_handle:
                    file_handle.write(png_bytes)
            except Exception as excp:
                vollog.error(f"Unable to write screenshot {filename}: {excp}")
                status = f"Error writing {filename}: {excp}"

            yield (
                0,
                (
                    sess_id,
                    station_name,
                    desktop_name,
                    len(win_entries),
                    f"{width}x{height}",
                    status,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Session", int),
                ("WindowStation", str),
                ("Desktop", str),
                ("Windows Drawn", int),
                ("Resolution", str),
                ("Output File", str),
            ],
            self._generator(),
        )
