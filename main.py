import re
import json

name = plugin_name = url = down = os = None

rounded = r"\(([^()]*?)\)"
square = r"\[([^\[\]]*?)\]"

data = []
with open("README.md", "r") as f:
    for line in f:
        line = line.strip()
        if line.startswith("##"):
            if m := re.search(square, line):
                name = m[1]
        elif line.startswith("- "):
            if m := re.findall(square, line):
                if len(m) == 1:
                    os = ""
                    plugin_name = m[0]
                elif len(m) == 2:
                    match (m[0]):
                        case "🐧":
                            os = "linux"
                        case "🪟":
                            os = "windows"
                        case "🍏":
                            os = "mac"
                    plugin_name = m[1]
            if m := re.findall(rounded, line):
                if len(m) == 1:
                    down = ""
                    url = m[0]
                elif len(m) == 2:
                    down = m[0]
                    url = m[1]

                data.append([name, plugin_name, url, down, "", os])

with open("data.json", "w") as f:
    json.dump({"data": data}, f, indent=4, sort_keys=True)
