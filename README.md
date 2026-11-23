# orochi_plugins

## [Abyss Watcher](https://github.com/Abyss-W4tcher)

- [🐧](check_ftrace.zip) [check_ftrace](https://github.com/Abyss-W4tcher/volatility-scripts/blob/master/Volatility_contest_2023/plugins/check_ftrace.py) - [2025-02-09] Detects Linux ftrace kernel hooks (built-in in Volatility 3: `linux.tracing.ftrace`)
- [🐧](check_tracepoints.zip) [check_tracepoints](https://github.com/Abyss-W4tcher/volatility-scripts/blob/master/Volatility_contest_2023/plugins/check_tracepoints.py) - [2025-02-09] Detects hooked Linux kernel tracepoints (built-in in Volatility 3: `linux.tracing.tracepoints`)
- [🐧](check_unlinked_modules.zip) [check_unlinked_modules](https://github.com/Abyss-W4tcher/volatility-scripts/blob/master/Volatility_contest_2023/plugins/check_unlinked_modules.py) - [2025-02-09] Finds hidden/unlinked Linux kernel modules (built-in in Volatility 3: `linux.hidden_modules`)

## [Airbus CERT](https://github.com/airbus-cert)

- [](scrings.zip) [scrings](https://github.com/airbus-cert/scrings/blob/main/volatility/scrings.py) - [2025-02-19] Extracts semantically valid script/code strings from memory using tree-sitter
- [🪟](vadscrings.zip) [vadscrings](https://github.com/airbus-cert/scrings/blob/main/volatility/vadscrings.py) - [2025-02-19] Scans Windows process VADs for semantically valid script/code strings via scrings

## [Asaf Eitani](https://github.com/AsafEitani)

- [🐧](ebpf_programs.zip) [eBPF Programs](https://github.com/AsafEitani/ebpf_programs_plugin) - [2023-07-19] Lists loaded Linux eBPF programs (built-in in Volatility 3: `linux.ebpf`)

## [Aviel Zohar and Or Chechik](https://github.com/memoryforensics1)

- [🪟]() [vol3xp](https://github.com/memoryforensics1/Vol3xp) - [2023-01-03] Interactive memory forensics explorer and analysis helper for Volatility 3
- [🪟]() [PackerList](https://github.com/memoryforensics1/Volatility.PE-Shellcode/blob/main/listpackers.py) - [2024-01-09] Identifies packed PE binaries in Windows process memory
- [🪟]() [MasqueradeProcess](https://github.com/memoryforensics1/Volatility.PE-Shellcode/blob/main/masqueradeprocess.py) - [2024-01-09] Detects process masquerading by comparing PEB and EPROCESS paths/names
- [🪟]() [DirectSyscalls](https://github.com/memoryforensics1/Volatility.PE-Shellcode/blob/main/directsyscalls.py) - [2024-01-09] Detects direct syscall stubs used to bypass user-mode EDR hooks
- [🪟]() [ApiHash](https://github.com/memoryforensics1/Volatility.PE-Shellcode/blob/main/apihash.py) - [2024-01-09] Detects API hashing shellcode patterns in process memory

## [BoB10th-BTC](https://github.com/BoB10th-BTC)

- [🪟]() [CryptoScan](https://github.com/BoB10th-BTC/CryptoScan) - [2021-12-16] Scans Windows memory for cryptocurrency wallet artifacts and keys

## [daddycocoaman](https://github.com/daddycocoaman)

- [🪟](dumpcerts.zip) [dumpcerts](https://github.com/daddycocoaman/volplugins/blob/main/plugins/dumpcerts.py) - [2023-03-22] Carves X.509 certificates and private keys from Windows memory
- [🪟](daddycocoaman_pypykatz.zip) [pypykatz](https://github.com/daddycocoaman/volplugins/blob/main/plugins/pypykatz.py) - [2023-03-22] Extracts Windows credentials from LSASS using pypykatz (updated Vol3 fork)
- [🪟](symcrypt.zip) [symcrypt](https://github.com/daddycocoaman/volplugins/blob/main/plugins/symcrypt.py) - [2023-03-22] Extracts Windows SymCrypt RSA private keys from memory

## [Daniel Baier (monkeywave)](https://github.com/monkeywave)

- [🐧]() [XFRM Inspector](https://github.com/monkeywave/XFRM-Inspector) - [2025-12-21] Recovers Linux IPsec XFRM Security Associations, policies, and encryption keys

## [f-block](https://github.com/f-block/volatility-plugins)

- [🪟]() [apisearch](https://github.com/f-block/volatility-plugins/blob/main/apisearch.py) - [2025-04-22] Searches Windows memory for API references and call targets
- [🪟]() [imgmalfind](https://github.com/f-block/volatility-plugins/blob/main/imgmalfind.py) - [2025-04-22] Detects maliciously modified or injected PE image sections
- [🪟]() [pe_parser](https://github.com/f-block/volatility-plugins/blob/main/pe_parser.py) - [2025-04-22] Parses PE headers and structures from process memory
- [🪟]() [pte_resolve](https://github.com/f-block/volatility-plugins/blob/main/pte_resolve.py) - [2025-04-22] Resolves virtual addresses via Windows Page Table Entries (PTEs)
- [🪟]() [ptemalfind](https://github.com/f-block/volatility-plugins/blob/main/ptemalfind.py) - [2025-04-22] Detects code injection by inspecting executable Page Table Entries (PTEs)
- [🪟]() [ptenum](https://github.com/f-block/volatility-plugins/blob/main/ptenum.py) - [2025-04-22] Enumerates Windows Page Table Entries (PTEs) for processes
- [🪟]() [simple_pteenum](https://github.com/f-block/volatility-plugins/blob/main/simple_pteenum.py) - [2025-04-22] Lightweight Page Table Entry (PTE) enumerator for Windows processes
- [🪟]() [swap_enum](https://github.com/f-block/volatility-plugins/blob/main/swap_enum.py) - [2025-04-22] Enumerates paged-out / swap-backed memory pages via PTEs

## [forensicxlab](https://github.com/forensicxlab/)

- [🪟](anydesk.zip) [anydesk](https://github.com/forensicxlab/volatility3_plugins/blob/main/anydesk.py) - [2026-10-18] Extracts AnyDesk remote-access session logs and artifacts from memory
- [🐧](inodes.zip) [inodes](https://github.com/forensicxlab/volatility3_plugins/blob/main/inodes.py) - [2026-10-18] Lists Linux inodes, permissions, and timestamps from memory
- [🪟](keepass.zip) [keepass](https://github.com/forensicxlab/volatility3_plugins/blob/main/keepass.py) - [2026-10-18] Extracts KeePass master password artifacts (CVE-2023-32784) from memory
- [🪟]() [mftscan](https://github.com/forensicxlab/volatility3/blob/feature/ADS/volatility3/framework/plugins/windows/mftscan.py) - [2026-10-19] Scans memory for NTFS MFT records and ADS (built-in in Volatility 3: `windows.mftscan`)
- [🪟](prefetch.zip) [prefetch](https://github.com/forensicxlab/volatility3_plugins/blob/main/prefetch.py) - [2026-10-18] Recovers and parses Windows Prefetch (.pf) execution artifacts from memory
- [🪟]() [Import Address Table](https://github.com/forensicxlab/volatility3/tree/feature/IAT) - [2026-10-19] Extracts PE Import Address Tables (built-in in Volatility 3: `windows.iat`)

## [fox-it](https://github.com/fox-it)

- [🐧]() [openssh_sessionkeys](https://github.com/fox-it/OpenSSH-Session-Key-Recovery/tree/main/volatility3) - [2024-05-22] Recovers OpenSSH session encryption keys from Linux memory

## Gerhart

- [🪟]() [Hyper-V](https://github.com/volatilityfoundation/community3/tree/master/Gerhart_Hyper_V) - [2023-03-19] Analyzes Microsoft Hyper-V virtual machine structures in memory

## [HalaAli198](https://github.com/HalaAli198)

- [Python Runtime Analysis](https://github.com/HalaAli198/Volatility-3-Plugins-for-Python-Runtime-Analysis) - [2026-06-13] Inspects Python classes, modules, bytecode, and stack variables in Windows/Linux memory

## [its-radio](https://github.com/its-radio)

- [🪟](chrome_hx.zip) [chrome_hx](https://github.com/its-radio/volatility_plugins/tree/main/chrome_hx) - [2025-05-17] Carves and parses Google Chrome SQLite browsing history directly from RAM

## [jpc-cert](https://github.com/JPCERTCC)

- [🪟]() [etw-scan](https://github.com/JPCERTCC/etw-scan/blob/main/plugins/etwscan.py) - [2024-11-15] Scans Event Tracing for Windows (ETW) sessions and recovers unflushed ETL events
- [🪟](pehash.zip) [Impfuzzy](https://github.com/JPCERTCC/impfuzzy/tree/master/impfuzzy_for_Volatility3) - [2022-08-26] Computes ImpHash, ImpFuzzy, and SSDEEP hashes for loaded Windows PE binaries

## [Kartik Iyer & Parag Rughani](https://github.com/KartikIyerr)

- [🪟](apcwatch.zip) [APCWatch](https://github.com/KartikIyerr/APCWatch-and-MalAPC/blob/main/apcwatch.py) - [2026-10-25] Enumerates and baselines Windows Asynchronous Procedure Calls (APCs)
- [🪟](malapc.zip) [MalAPC](https://github.com/KartikIyerr/APCWatch-and-MalAPC/blob/main/malapc.py) - [2026-10-25] Detects malicious APC injection and suspicious queued APC routines
- [🪟]() [TlsCheck](https://github.com/KartikIyerr/TlsCheck) - [2025-04-26] Detects and analyzes Thread Local Storage (TLS) callbacks in PE binaries

## [kevthehermit](https://github.com/kevthehermit)

- [🪟]() [cobaltstrike](https://github.com/kevthehermit/volatility_plugins/tree/main/vol3/cobaltstrike) - [2023-07-22] Detects Cobalt Strike beacons and extracts C2 configurations from memory
- [🪟]() [passwordmanagers](https://github.com/kevthehermit/volatility_plugins/tree/main/vol3/passwordmanagers) - [2023-07-22] Extracts password manager vaults and credentials from Windows memory
- [🪟]() [richheader](https://github.com/kevthehermit/volatility_plugins/tree/main/vol3/richheader) - [2023-07-22] Extracts and hashes PE Rich Headers from loaded Windows modules
- [🪟]() [zone-identifier](https://github.com/kevthehermit/volatility_plugins/tree/main/vol3/zone-identifier) - [2023-07-22] Recovers Mark-of-the-Web (Zone.Identifier) ADS artifacts from memory

## Moreira

- [🐧]() [mountinfo](https://github.com/volatilityfoundation/community3/tree/master/Moreira_Mountinfo/vol3_mountinfo_plugin_files/volatility/framework) - [2023-03-19] Lists Linux mount namespaces and mount points (built-in in Volatility 3: `linux.mountinfo`)
- [🐧]() [netfilter](https://github.com/volatilityfoundation/community3/tree/master/Moreira_Netfilter) - [2023-03-19] Inspects Linux netfilter hooks (built-in in Volatility 3: `linux.netfilter`)

## @oshaked1-@amir9339

- [🐧]() [docker](https://github.com/amir9339/volatility-docker) - [2024-01-10] Identifies Docker containers, cgroups, and namespaces in Linux memory

## [orchechik](https://github.com/orchechik)

- [🪟]() [check_spoof](https://github.com/orchechik/check_spoof) - [2023-05-02] Detects PPID and process parameter spoofing in Windows memory

## [orochi_plugins](https://github.com/dadokkio/orochi_plugins)

- [🪟](apihooks.zip) [apihooks](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Detects user-mode inline API hooks (JMP/CALL/trampolines) in exported DLL functions
- [🐧](linux_arp.zip) [linux_arp](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Extracts the Linux kernel IPv4 ARP/neighbor cache from arp_tbl
- [🐧](linux_check_fop.zip) [linux_check_fop](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Audits Linux file_operations/proc_ops pointers on /proc and open files for rootkit hooks
- [🪟](screenshot.zip) [screenshot](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Generates wireframe PNG screenshots of Windows desktops from tagWND structures
- [🪟](shellbags.zip) [shellbags](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Parses BagMRU Shell Items from UsrClass.dat and NTUSER.DAT registry hives
- [🪟](shutdowntime.zip) [shutdowntime](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Extracts the last Windows shutdown timestamp from the SYSTEM registry hive
- [🪟](token_stealing.zip) [token_stealing](https://github.com/dadokkio/orochi_plugins) - [2026-11-23] Detects Windows kernel token stealing and unexpected SYSTEM _TOKEN sharing

## [Rifqi Ramadhan](https://github.com/spitfirerxf)

- [🪟](notepad.zip) [notepad](https://github.com/spitfirerxf/vol3-plugins/blob/main/notepad.py) - [2026-06-18] Recovers unsaved text content from Windows Notepad process memory
- [🪟]() [kusertime](https://github.com/spitfirerxf/vol3-plugins/blob/main/kusertime.py) - [2026-06-18] Extracts system time from Windows KUSER_SHARED_DATA
- [🪟]() [evtxlog](https://github.com/spitfirerxf/vol3-plugins/blob/main/evtxlog.py) - [2026-06-18] Carves Windows EVTX event log chunks from memory
- [🪟]() [sticky](https://github.com/spitfirerxf/vol3-plugins/blob/main/sticky.py) - [2026-06-18] Recovers Windows Sticky Notes content from memory

## Silva

- [🪟]() [multi-yara](https://github.com/volatilityfoundation/community3/tree/master/Silva_Multi_Yara) - [2023-03-19] Runs multiple YARA rulesets concurrently across Windows memory

## [skelsec](https://github.com/skelsec)

- [🪟](pypykatz.zip) [pypykatz](https://github.com/skelsec/pypykatz-volatility3) - [2025-05-30] Extracts Windows credentials, NTLM hashes, and Kerberos tickets from LSASS via pypykatz

## Stelte

- [🪟]() [evtx](https://github.com/volatilityfoundation/community3/tree/master/Stelte_Evtx) - [2023-03-19] Extracts and parses Windows Event Logs (EVTX) from memory
- [🐧]() [syslog](https://github.com/volatilityfoundation/community3/tree/master/Stelte_Syslog) - [2023-03-19] Recovers Linux syslog messages from memory

## [Telindus-CSIRT](https://github.com/Telindus-CSIRT)

- [🪟](autorun.zip) [Volatility3-autoruns](https://github.com/Telindus-CSIRT/volatility3-autoruns) - [2022-04-27] Enumerates Windows persistence mechanisms (Run keys, services, tasks, AppInit, Winlogon)

## [Valentin Obst](https://github.com/vobst)

- [🐧]() [bpf_graph](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_graph.py) - [2024-01-19] Generates a relationship graph of Linux eBPF programs, maps, links, and processes
- [🐧]() [bpf_listlinks](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_listlinks.py) - [2024-01-19] Lists active Linux eBPF links in kernel memory
- [🐧]() [bpf_listmaps](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_listmaps.py) - [2024-01-19] Lists Linux eBPF maps and metadata from kernel memory
- [🐧]() [bpf_listprocs](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_listprocs.py) - [2024-01-19] Lists Linux processes holding open eBPF file descriptors
- [🐧]() [bpf_listprogs](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_listprogs.py) - [2024-01-19] Lists loaded Linux eBPF programs and details from kernel memory
- [🐧]() [bpf_lsm](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_lsm.py) - [2024-01-19] Inspects Linux eBPF LSM (Linux Security Modules) hooks
- [🐧]() [bpf_netdev](https://github.com/vobst/BPFVol3/blob/main/src/plugins/bpf_netdev.py) - [2024-01-19] Lists eBPF programs attached to Linux network devices (XDP/TC)
