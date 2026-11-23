# Custom Volatility 3 Plugins (`orochi_plugins`)

This directory contains custom Volatility 3 plugins (targeting Volatility 3 `>= 2.28` / Orochi) ported from missing Volatility 2 capabilities or written specifically for DFIR and threat hunting.

Each plugin is also packaged at the repository root as a flat Orochi-compatible `.zip` archive (with `requirements.txt` where needed).

## Overview

| Plugin | Volatility 3 Name | OS | Package | Extra Dependencies |
| --- | --- | --- | --- | --- |
| [apihooks.py](apihooks.py) | `custom.apihooks.ApiHooks` | Windows | `../apihooks.zip` | `capstone`, `pefile` *(pre-installed in Orochi)* |
| [screenshot.py](screenshot.py) | `custom.screenshot.Screenshot` | Windows | `../screenshot.zip` | `pillow` *(pre-installed in Orochi)* |
| [shellbags.py](shellbags.py) | `custom.shellbags.ShellBags` | Windows | `../shellbags.zip` | None |
| [shutdowntime.py](shutdowntime.py) | `custom.shutdowntime.ShutdownTime` | Windows | `../shutdowntime.zip` | None |
| [token_stealing.py](token_stealing.py) | `custom.token_stealing.TokenStealing` | Windows | `../token_stealing.zip` | None |
| [linux_arp.py](linux_arp.py) | `custom.linux_arp.Arp` | Linux | `../linux_arp.zip` | None |
| [linux_check_fop.py](linux_check_fop.py) | `custom.linux_check_fop.CheckFop` | Linux | `../linux_check_fop.zip` | None |

---

## Installation & General Usage

### In Orochi
Upload the corresponding `.zip` file from the repository root via the Orochi Admin / Plugins interface (or sync via `plugins_sync`). Orochi automatically installs any `requirements.txt` across Django and Dask workers and registers the plugin under `custom.<module>.<Class>`.

### Standalone Volatility 3 CLI
Point Volatility 3 to the `plugins/` directory with `-p` / `--plugin-dirs`:

```bash
vol -p /path/to/orochi_plugins/plugins -f <memory_dump> <plugin_name> [options]
```

*(When loaded via `-p`, Volatility 3 exposes the plugin directly as `<module>.<Class>`, e.g. `shellbags.ShellBags`; inside Orochi it is exposed under `custom.<module>.<Class>`.)*

---

## Windows Plugins

### `apihooks` (`ApiHooks`)
Detects user-mode inline API hooks on exported DLL functions by reading each module's PE Export Directory and disassembling the first instructions of every exported function with `capstone`.

**Detected hook patterns:**
- Direct relative `JMP` / `CALL` pointing outside the exporting module
- Indirect `JMP [rip+disp]` / `CALL [imm]` resolving outside the module
- `MOV reg, <imm>; JMP/CALL reg` trampolines
- `PUSH <imm>; RET` trampolines

Target addresses are resolved against loaded process modules (or flagged as `<unbacked>` when jumping into unbacked/private memory).

**Options:**
- `--pid <PID [PID ...]>` — filter on specific process IDs
- `--dll <SUBSTRING>` — filter on module name (e.g. `ntdll.dll`, `kernel32.dll`)

**Examples:**
```bash
vol -p plugins -f memory.raw apihooks.ApiHooks --pid 1234 --dll ntdll.dll
```

**Example output:**
```text
PID   Process         Module     Function          Hook Type           Hook Address    Target Address  Target Module  Disassembly
1234  powershell.exe  ntdll.dll  EtwEventWrite     Inline JMP          0x7ff812345670  0x1a2b00001000  <unbacked>     jmp 0x1a2b00001000
1234  powershell.exe  ntdll.dll  NtAllocateVirtual MOV+JMP Trampoline  0x7ff812349120  0x7ff700014200  hook_edr.dll   mov rax, 0x7ff700014200; jmp rax
```

---

### `screenshot` (`Screenshot`)
Generates wireframe PNG screenshots of Windows desktops from `tagWND` structures (supporting both legacy `tagWND.rcWindow` and Windows 10 >= 17134 `subPointer.rcWindow`). Each desktop is rendered as a PNG with window borders, title bars, window titles, process names, and PIDs, and saved via Volatility 3's file output handler (`-o`).

**Options:**
- `--all-windows` — include non-visible windows (by default only `WS_VISIBLE` windows are drawn)

**Examples:**
```bash
vol -p plugins -o ./out -f memory.raw screenshot.Screenshot
vol -p plugins -o ./out -f memory.raw screenshot.Screenshot --all-windows
```

**Example output:**
```text
Session  WindowStation  Desktop  Windows Drawn  Resolution  Output File
1        WinSta0        Default  14             1920x1080   session_1.WinSta0.Default.png
```

---

### `shellbags` (`ShellBags`)
Recursively parses `BagMRU` Shell Items from `UsrClass.dat` and `NTUSER.DAT` registry hives in memory to reconstruct folders, removable drives, and network shares browsed by users. Supports Root Folder GUIDs, Volume/Drive entries, File/Directory entries (including `0xBEEF0004` Unicode long filenames and DOS Modified/Accessed/Created timestamps), Network shares, and URIs. Implements `TimeLinerInterface`.

**Options:**
- `--offset <HEX_OFFSET>` — inspect a specific registry hive offset

**Examples:**
```bash
vol -p plugins -f memory.raw shellbags.ShellBags
```

**Example output:**
```text
Hive                                    Registry Key                                                      Last Write Time            Shell Item Type  Path                         Modified                   Accessed                   Created
\??\C:\Users\alice\AppData\...\UsrClass Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0          2026-11-20 09:14:22+00:00  RootFolder       My Computer                  -                          -                          -
\??\C:\Users\alice\AppData\...\UsrClass Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\1        2026-11-20 09:14:25+00:00  Volume           My Computer\C:\              -                          -                          -
\??\C:\Users\alice\AppData\...\UsrClass Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\1\0      2026-11-20 09:15:02+00:00  Directory        My Computer\C:\ExfilStaging  2026-11-20 09:14:58+00:00  2026-11-20 09:15:02+00:00  2026-11-20 09:14:10+00:00
```

---

### `shutdowntime` (`ShutdownTime`)
Reads `Select\Current` from the `SYSTEM` registry hive in memory to locate the active `ControlSet00X` and extracts `Control\Windows\ShutdownTime` as a UTC timestamp. Implements `TimeLinerInterface`.

**Options:**
- `--offset <HEX_OFFSET>` — inspect a specific `SYSTEM` hive offset

**Examples:**
```bash
vol -p plugins -f memory.raw shutdowntime.ShutdownTime
```

**Example output:**
```text
Hive Offset         Registry                                   ControlSet     ShutdownTime
0xffffc18a40215000  \REGISTRY\MACHINE\SYSTEM                   ControlSet001  2026-11-22 21:43:11+00:00
```

---

### `token_stealing` (`TokenStealing`)
Inspects `_EPROCESS.Token` (`_EX_FAST_REF`) pointers across all processes to detect kernel token stealing and privilege escalation:
- Non-system processes sharing the exact `_TOKEN` kernel object of `System` (PID 4)
- Multiple processes unexpectedly sharing the same `_TOKEN` pointer
- Common user-mode parents (`explorer.exe`, `cmd.exe`, `powershell.exe`, browsers, Office) spawning a process with PID 4's `SYSTEM` token

**Options:**
- `--all` — display all processes with their `_TOKEN` address instead of only suspicious matches

**Examples:**
```bash
vol -p plugins -f memory.raw token_stealing.TokenStealing
vol -p plugins -f memory.raw token_stealing.TokenStealing --all
```

**Example output:**
```text
PID   PPID  Process  Parent        Token Address       Shared With  Assessment
4812  2048  cmd.exe  explorer.exe  0xffffc18a40004050  System(4)    Shares PID 4 SYSTEM _TOKEN; Shared _TOKEN with 1 other process(es); User-mode parent (explorer.exe) with SYSTEM _TOKEN
```

---

## Linux Plugins

### `linux_arp` (`Arp`)
Extracts IPv4 neighbor / ARP cache entries from the Linux kernel's `arp_tbl` (`struct neigh_table` → `nht->hash_buckets`), displaying IP address, MAC address, network interface name, and decoded `NUD_*` state flags (`REACHABLE`, `STALE`, `DELAY`, `PROBE`, `PERMANENT`, `FAILED`, etc.).

**Examples:**
```bash
vol -p plugins -f linux.lime linux_arp.Arp
```

**Example output:**
```text
IP Address     MAC Address        Interface  State      Offset
192.168.1.1    aa:bb:cc:dd:ee:01  eth0       REACHABLE  0xffff9b2c04128800
192.168.1.42   de:ad:be:ef:00:10  eth0       STALE      0xffff9b2c04128c00
```

---

### `linux_check_fop` (`CheckFop`)
Audits `file_operations` and `proc_ops` callback pointers (e.g. `iterate_shared`, `iterate`, `readdir`, `read`, `write`, `open`, `unlocked_ioctl`) across:
1. `/proc` (`proc_root` and child `proc_dir_entry` structures, supporting both `< 5.6` `proc_fops` and `>= 5.6` `proc_ops`)
2. Open file descriptors of running processes

Resolves each handler address against known kernel symbols and loaded modules (`lsmod`) to flag pointers resolving to `UNKNOWN` (typical of LKM rootkits).

**Options:**
- `--all` — output all non-NULL callbacks instead of only suspicious/unknown handlers

**Examples:**
```bash
vol -p plugins -f linux.lime linux_check_fop.CheckFop
vol -p plugins -f linux.lime linux_check_fop.CheckFop --all
```

**Example output:**
```text
Source     Target                  Member          Handler Address     Module   Symbol
procfs     /proc                   iterate_shared  0xffffffffc04a1120  UNKNOWN  UNKNOWN
open_file  sshd(812) fd=3 /etc/..  read            0xffffffffc04a1480  UNKNOWN  UNKNOWN
```

---

## Testing

From the repository root:

```bash
# Validate catalog, zip structure, and URLs
python3 test_plugins.py --check-urls

# Validate loading and requirements against a Volatility 3 environment
python3 test_plugins.py --vol-python /path/to/venv/bin/python --install-deps
```
