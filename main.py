import json
import re

OS_MAP = {
    "🐧": "Linux",
    "🪟": "Windows",
    "🍏": "Mac",
    "🌐": "",
}

LINK_RE = re.compile(r"\[([^\[\]]*?)\]\(([^()]*?)\)")


def _strip_link_text(cell: str) -> str:
    m = LINK_RE.search(cell)
    return m.group(1).strip() if m else cell.strip()


def _extract_link(cell: str) -> tuple[str, str]:
    m = LINK_RE.search(cell)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return cell.strip(), ""


data = []
in_catalog_table = False

with open("README.md", "r", encoding="utf-8") as f:
    for raw_line in f:
        line = raw_line.strip()
        if not line.startswith("|"):
            in_catalog_table = False
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 6 and cells[0].lower() == "author" and cells[1].lower() == "plugin":
            in_catalog_table = True
            continue
        if not in_catalog_table or len(cells) < 6:
            continue
        # Skip separator row
        if set(cells[0].replace("-", "").replace(":", "").strip()) == set() and "-" in cells[0]:
            continue

        author = _strip_link_text(cells[0])
        plugin_name, url = _extract_link(cells[1])
        os_name = OS_MAP.get(cells[2], "")
        pkg_text, pkg_url = _extract_link(cells[3])
        down = pkg_url if pkg_url else ("" if pkg_text in ("", "-") else pkg_text)
        last_update = "" if cells[4] in ("", "-") else cells[4]
        desc = cells[5].replace("\\|", "|").replace("`", "").strip()
        info = f"[{last_update}] {desc}".strip() if last_update else desc

        data.append([author, plugin_name, url, down, info, os_name])

with open("data.json", "w", encoding="utf-8") as f:
    json.dump({"data": data}, f, indent=4, sort_keys=True)
    f.write("\n")
