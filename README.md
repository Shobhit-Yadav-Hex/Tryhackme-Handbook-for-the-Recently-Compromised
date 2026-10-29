# TryHackMe: Handbook for the Recently Compromised

![Platform](https://img.shields.io/badge/Platform-TryHackMe-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Category](https://img.shields.io/badge/Category-DFIR%20%2F%20Log%20Analysis-blue)

Writeup for the TryHackMe room **Handbook for the Recently Compromised**. A Windows workstation was flagged for unusual activity. The task is to analyse the exported Windows event logs, rebuild the attack timeline, and map the attacker's actions to MITRE ATT&CK.

Room: https://tryhackme.com/room/handbookfortherecentlycompromised

> Flag and exact answers are intentionally left out. TryHackMe asks people not to publish them. Follow the method below and you will get there yourself.

---

## Evidence

| File | Description |
|------|-------------|
| `Microsoft-Windows-Sysmon%4Operational.evtx` | Sysmon process, file and registry events |
| `PowerShell-Operational.evtx` | PowerShell script block logs (Event ID 4104) |
| `tools/evtx_dump` | Rust-based EVTX parser (provided on the AttackBox) |
| `tools/attack-reference/` | Offline MITRE ATT&CK reference (`enterprise-techniques.tsv`) |

## Tools Used

- `evtx_dump` to convert `.evtx` to JSON lines
- `grep`, `python3`, `base64` for searching and decoding
- Offline MITRE ATT&CK reference

---

## Methodology

### 1. Convert the logs to searchable text

```bash
cd ~/Desktop/artifacts
./tools/evtx_dump -o jsonl "Microsoft-Windows-Sysmon%4Operational.evtx" > sysmon.json
./tools/evtx_dump -o jsonl PowerShell-Operational.evtx > ps.json
wc -l sysmon.json ps.json
```

### 2. Find the suspicious command (wildcard obfuscation)

The question hints that a trusted utility was called with a wildcard in its name. Searching Sysmon for commands containing `*`:

```bash
grep '\*' sysmon.json | grep -oP '"CommandLine":"(\\.|[^"\\])*"' | cut -c1-500 | sort -u
```

A hidden PowerShell command resolved the binary at runtime with `gci C:\Windows\System32\certu*.exe`, so the tool name never appears directly in the command line. The same download then shows up again with the real binary name. This is a **LOLBin** abuse pattern.

### 3. Recover the download URL

```bash
grep -aoiE 'https?://[^ "\\]+' sysmon.json ps.json | sort -u
```

The `-urlcache -f <URL> <output>` arguments reveal where the second-stage script was fetched from and where it was saved.

### 4. Dump the full Sysmon timeline

Searching only for `wscript`/`cscript` returned nothing, so I printed every process, file and registry field instead:

```bash
grep -aoE '"(Image|ParentImage|CommandLine|TargetFilename|TargetObject)":"(\\.|[^"\\])*"' sysmon.json | cut -c1-300
```

Key observations from the timeline:

1. `explorer.exe` launched `mshta.exe` against an `.hta` file in the user's Downloads folder. This is the initial attachment.
2. `mshta.exe` spawned a hidden `powershell.exe` (`-nop -w hidden -c ...`).
3. PowerShell used `certutil` to download a second-stage `.ps1` into `%TEMP%`.
4. The downloaded script ran with `-ep bypass`.
5. The script created a scheduled task using `schtasks /create ... /sc onlogon /rl highest`.
6. `wevtutil cl` was used to clear the Sysmon and PowerShell logs.

The `Run\MicrosoftEdgeAutoLaunch...` registry value in the logs belongs to Edge and is a normal entry, not attacker persistence.

### 5. Map to MITRE ATT&CK using the offline reference

```bash
grep -i "mshta" tools/attack-reference/enterprise-techniques.tsv
grep -i "scheduled task" tools/attack-reference/enterprise-techniques.tsv
```

### 6. Read the PowerShell script block logs

```bash
grep -aoE '"(ScriptBlockText|Payload|ContextInfo)":"(\\.|[^"\\])*"' ps.json | cut -c1-600
```

Script block logging (Event ID 4104) captured the second-stage script content. The script used **string splitting** (`'a'+'b'` and `-join(...)`) so that simple greps for keywords would miss it. Reassembling the pieces reveals a Base64 blob, which is decoded with:

```bash
echo '<reassembled_base64>' | base64 -d
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Defense Evasion / Execution | System Binary Proxy Execution: Mshta | T1218.005 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command and Control | Ingress Tool Transfer (certutil download) | T1105 |
| Defense Evasion | Obfuscated Files or Information (wildcard, string splitting, Base64) | T1027 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |

## Attack Chain Summary

```
pipeline-check.hta (user double-click)
        |
        v
mshta.exe  --->  hidden powershell.exe
                        |
                        v
        certutil (resolved via wildcard) downloads pipeline-sync.ps1
                        |
                        v
        pipeline-sync.ps1 runs (-ep bypass)
                        |
          +-------------+-------------+
          v                           v
  schtasks onlogon persistence   obfuscated payload / beacon
                        |
                        v
        wevtutil cl  (log clearing)
```

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| File | `pipeline-check.hta` (Downloads) |
| File | `pipeline-sync.ps1` (Temp and Roaming\PipelineSync) |
| Domain | `pipeline-cdn.thm` (port 8088) |
| Scheduled task | `StudioPipelineSync` |

## Detection Ideas

- Alert on `mshta.exe` launched by `explorer.exe` with a file in `Downloads`.
- Alert on `mshta.exe` spawning `powershell.exe` or `cmd.exe`.
- Alert on `certutil.exe` with `-urlcache` or `-f` and an HTTP URL.
- Alert on PowerShell with `-nop -w hidden -ep bypass`.
- Alert on `schtasks /create` with `/sc onlogon` and `/rl highest` from a script.
- Alert on `wevtutil cl` (also Security Event ID 1102 and System Event ID 104).
- Enable PowerShell Script Block Logging so obfuscated scripts are still recorded.

## Lessons Learned

- Start with a full timeline, not a single keyword. My first assumption (`wscript`/`cscript`) was wrong, and the full dump showed the real initial access (`mshta.exe`).
- Wildcards and string splitting defeat naive keyword searches. Look for the behaviour (child processes, network arguments), not just the tool name.
- Verify tool names from the `Image` field, not from guesses.
- Always confirm MITRE IDs against the reference instead of relying on memory.

---

*Written by Shubham Yadav | Cybersecurity learner, CTF and DFIR practice*
