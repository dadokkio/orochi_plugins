import re
import json

OS_MAP = {
    "🐧": "Linux",
    "🪟": "Windows",
    "🍏": "Mac",
}

LINK_RE = re.compile(r"\[([^\[\]]*?)\]\(([^()]*?)\)")
SQUARE_RE = re.compile(r"\[([^\[\]]*?)\]")

name = None
data = []

with open("README.md", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line.startswith("## "):
            if m := SQUARE_RE.search(line):
                name = m.group(1).strip()
            else:
                name = line[3:].strip()
        elif line.startswith("- "):
            links = LINK_RE.findall(line)
            if not links:
                continue

            os_name = ""
            down = ""
            if len(links) == 1:
                plugin_name, url = links[0]
            else:
                os_icon, down = links[0]
                os_name = OS_MAP.get(os_icon.strip(), "")
                plugin_name, url = links[1]

            data.append([name, plugin_name.strip(), url.strip(), down.strip(), "", os_name])

with open("data.json", "w", encoding="utf-8") as f:
    json.dump({"data": data}, f, indent=4, sort_keys=True)
    f.write("\n")
