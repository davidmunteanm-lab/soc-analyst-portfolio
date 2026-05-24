# MITRE ATT&CK — Quick Reference

A compact map of MITRE ATT&CK techniques I've encountered in TryHackMe rooms, paired with the artefacts they leave behind and where to look for them. Not exhaustive — just the ones I've actually seen and want to recognize again.

## Initial Access

### T1566 — Phishing

The classic. Sub-techniques worth knowing:

- **T1566.001** Spearphishing Attachment — malicious file in the email.
- **T1566.002** Spearphishing Link — link to a malicious site.

**What to look for**
- Email gateway logs with `Authentication-Results: spf=fail` or `dmarc=fail`.
- Mismatch between `From:` domain and `Return-Path:` / `Reply-To:`.
- URLs pointing to free TLDs (`.tk`, `.gq`, `.cf`) or punycode look-alikes.
- Attachments with double extensions (`invoice.pdf.exe`).

This is exactly what my [phishing-analyzer](../tools/phishing-analyzer/) tool tries to detect statically.

## Execution

### T1059 — Command and Scripting Interpreter

- **T1059.001** PowerShell
- **T1059.003** Windows Command Shell

**What to look for**
- Windows Event 4688 (process creation) with `powershell.exe` or `cmd.exe` and unusual parent processes (`winword.exe`, `outlook.exe`).
- Sysmon Event 1 with the same pattern.
- PowerShell Event 4104 (ScriptBlock logging) containing `-EncodedCommand`, `IEX`, `DownloadString`, `Invoke-WebRequest`.

## Persistence

### T1547.001 — Registry Run Keys / Startup Folder

**What to look for**
- Sysmon Event 13 (registry value set) under:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

### T1053.005 — Scheduled Task

**What to look for**
- Windows Event 4698 (scheduled task created).
- `schtasks.exe` or `at.exe` in process creation logs.

## Privilege Escalation

### T1068 — Exploitation for Privilege Escalation

**What to look for**
- Unexpected processes spawned with SYSTEM token (`integrity level System`).
- Crashes in privileged services preceding suspicious child processes.

## Defense Evasion

### T1027 — Obfuscated Files or Information

**What to look for**
- PowerShell with `-EncodedCommand` and a long base64 string.
- VBA macros using string concatenation to hide URLs (`"htt" & "ps://..."`).
- Process command lines unusually long or full of `%` characters (env var substitution).

### T1070.001 — Clear Windows Event Logs

**What to look for**
- Windows Event 1102 (audit log cleared) — almost always suspicious outside maintenance windows.
- Sudden gaps in normally-continuous log streams.

## Credential Access

### T1110 — Brute Force

- **T1110.001** Password Guessing
- **T1110.003** Password Spraying

**What to look for**
- Bursts of Event 4625 (failed logon) from a single source against many users (spraying) or one user (guessing).
- The Splunk transaction pattern in [splunk-spl-cheatsheet.md](splunk-spl-cheatsheet.md) catches the brute-force shape.

### T1003 — OS Credential Dumping

- **T1003.001** LSASS Memory

**What to look for**
- Sysmon Event 10 (process accessed another process) where the target is `lsass.exe` and the access right is `0x1010` or `0x1410`.
- `procdump.exe`, `mimikatz.exe`, or unusual processes touching `lsass.exe`.

## Discovery

### T1087 — Account Discovery

**What to look for**
- `net user`, `net group`, `whoami /all`, `Get-ADUser` in process command lines.

### T1018 — Remote System Discovery

**What to look for**
- `net view`, `ping` sweeps, `nslookup` for many hosts in short windows.

## Lateral Movement

### T1021.001 — Remote Desktop Protocol

**What to look for**
- Windows Event 4624 with `Logon Type 10` (RemoteInteractive).
- Spike in RDP connections from internal hosts to other internal hosts.

## Collection

### T1560 — Archive Collected Data

**What to look for**
- `7z.exe`, `rar.exe`, or PowerShell `Compress-Archive` running outside of normal backup windows, especially on a host that shouldn't be packaging files.

## Exfiltration

### T1041 — Exfiltration Over C2 Channel

**What to look for**
- Outbound traffic to an unusual destination with sustained high byte counts.
- DNS queries with abnormally long labels (DNS tunneling).
- HTTP POST requests with large bodies to domains with poor reputation.

## References

- [MITRE ATT&CK Matrix for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [DeTT&CT — mapping detections to ATT&CK](https://github.com/rabobank-cdc/DeTTECT)