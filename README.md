# BarnesLab SOC — Splunk SIEM + Attack Detection Lab

![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Platform](https://img.shields.io/badge/Platform-VMware%20Workstation-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Free-FF5733?logo=splunk)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

## Overview

BarnesLab SOC is Phase 2 of the BarnesLab home lab series. This project extends the existing Active Directory environment by adding a full Security Operations Center (SOC) monitoring layer — deploying Splunk as a SIEM, collecting endpoint telemetry via Sysmon and the Splunk Universal Forwarder, simulating real-world attacks from a Kali Linux attacker VM, and building detections that map to the MITRE ATT&CK framework.

This project demonstrates practical SOC analyst skills including log ingestion, event correlation, alert development, dashboard creation, and threat detection — all in a self-built lab environment.

📺 **Demo Video:** [Watch the BarnesLab SOC Build Walkthrough on YouTube](https://youtu.be/MdgM8zBHafw) *(link coming soon)*

➡️ **Prerequisite:** [BarnesLab Active Directory Home Lab](https://github.com/lbarnes86/barneslab-active-directory-lab)

---

## Lab Architecture

```
+---------------------------+        +---------------------------+
|      BARNESLAB-DC         |        |          WKSTN1           |
|  Windows Server 2022      |        |     Windows 10 Enterprise |
|  Domain Controller / DNS  |        |    Domain-Joined Client   |
|  IP: 192.168.10.10        |        |    IP: 192.168.10.20      |
|  [Sysmon + UF Installed]  |        |  [Sysmon + UF Installed]  |
+---------------------------+        +---------------------------+
           |                                      |
           |        barneslab.local               |
           |       VMware NAT Network             |
           |      Subnet: 192.168.10.0/24         |
           |                                      |
+---------------------------+        +---------------------------+
|     SPLUNK-SERVER         |        |       KALI-ATTACKER       |
|   Ubuntu Server 22.04     |        |        Kali Linux         |
|   Splunk Free SIEM        |        |    Attack Simulation VM   |
|   IP: 192.168.10.50       |        |    IP: 192.168.10.60      |
|   Port 8000 (Web UI)      |        |  Hydra / Nmap / MSFvenom  |
|   Port 9997 (Receiver)    |        |                           |
+---------------------------+        +---------------------------+
```

---

## Environment Specifications

| Component | Details |
|---|---|
| Host Machine | Lenovo ThinkCentre M73 Tiny |
| Host CPU | Intel Core i5-4570T (up to 3.6GHz) |
| Host RAM | 16GB |
| Host Storage | 128GB SSD |
| Virtualization Platform | VMware Workstation Pro 17 |
| SIEM Platform | Splunk Free (up to 500MB/day ingestion) |
| Endpoint Telemetry | Sysmon + Splunk Universal Forwarder |
| Attack Platform | Kali Linux |
| Detection Framework | MITRE ATT&CK |

---

## Virtual Machines

| VM Name | OS | Role | IP Address | RAM | Disk |
|---|---|---|---|---|---|
| BARNESLAB-DC | Windows Server 2022 | Domain Controller / DNS | 192.168.10.10 | 2GB | 40GB |
| WKSTN1 | Windows 10 Enterprise | Domain Workstation | 192.168.10.20 | 2GB | 30GB |
| SPLUNK-SERVER | Ubuntu Server 22.04 | Splunk SIEM | 192.168.10.50 | 2GB | 20GB |
| KALI-ATTACKER | Kali Linux | Attack Simulation | 192.168.10.60 | 2GB | 20GB |

---

## What I Built

### Endpoint Telemetry — Sysmon
- Deployed Sysmon on both BARNESLAB-DC and WKSTN1 using the SwiftOnSecurity configuration
- Sysmon provides enriched process creation, network connection, and file creation events beyond default Windows logging
- Verified telemetry in Event Viewer: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational

### Log Forwarding — Splunk Universal Forwarder
- Installed Splunk Universal Forwarder on both Windows VMs
- Configured `inputs.conf` to forward:
  - Windows Security Event Log (EventCode 4624, 4625, 4720, 4726, 4732, 4740)
  - Windows System Event Log
  - Sysmon Operational Log (process creation, network connections, PowerShell)
- All logs forwarded to Splunk Server on port 9997

### SIEM Deployment — Splunk on Ubuntu Server
- Deployed Ubuntu Server 22.04 as a dedicated Splunk host
- Installed Splunk Free and configured receiving on port 9997
- Validated log ingestion from both Windows VMs
- Built index, sourcetype, and host-based search filters

### Detection Engineering
Built the following custom Splunk searches and saved them as scheduled alerts:

| Detection Name | Splunk Search | MITRE Technique |
|---|---|---|
| Brute Force Login Attempts | `index=* EventCode=4625 \| stats count by src_ip, user \| where count > 10` | T1110 — Brute Force |
| Successful Login After Failures | `index=* EventCode=4625 \| append [search index=* EventCode=4624] \| transaction user \| where mvcount(EventCode)>1` | T1110.001 |
| PowerShell Encoded Command | `index=* EventCode=4688 CommandLine="*-enc*" OR CommandLine="*EncodedCommand*"` | T1059.001 — PowerShell |
| New Local User Created | `index=* EventCode=4720 \| table _time, user, src_user, host` | T1136 — Create Account |
| User Added to Privileged Group | `index=* EventCode=4732 \| table _time, user, Group_Name, host` | T1078 — Valid Accounts |
| Account Lockout | `index=* EventCode=4740 \| table _time, user, src, host` | T1110 — Brute Force |
| Nmap Port Scan Detected | `index=* sourcetype=XmlWinEventLog EventCode=5156 \| stats count by src_ip dest_port \| where count > 50` | T1046 — Network Service Discovery |
| Sysmon Process Creation — Suspicious | `index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image="*cmd.exe" OR Image="*powershell.exe" ParentImage="*winword.exe" OR ParentImage="*excel.exe"` | T1566 — Phishing |

### SOC Dashboard
Built a Splunk dashboard called **BarnesLab SOC Overview** with the following panels:
- Failed Login Attempts — Last 24 Hours (bar chart by user)
- Successful Logins — Last 24 Hours (table with user, source IP, host)
- Top Alert Types — Last 7 Days (pie chart)
- Sysmon Process Creation Events — Last Hour (table)
- Account Management Events (4720, 4726, 4732) — Timeline
- Active Alert Count by Severity (single value panels)

### Attack Simulations

The following attacks were simulated from the Kali Linux VM to generate real telemetry and validate detections:

**Attack 1 — Brute Force (T1110)**
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.10.10
```
Result: EventCode 4625 (failed logins) fired on DC, Splunk alert triggered after 10 failures

**Attack 2 — Network Reconnaissance (T1046)**
```bash
nmap -sV -p 1-1000 192.168.10.10
```
Result: Sysmon network connection events logged, port scan detection fired

**Attack 3 — PowerShell Encoded Command (T1059.001)**
```powershell
powershell -enc JABzAD0AIgBIAGUAbABsAG8AIgA7ACAAdwByAGkAdABlAC0AaABvAHMAdAAgACQAcwA=
```
Result: EventCode 4688 (process creation) with encoded command line captured, alert fired

**Attack 4 — New User Account Creation (T1136)**
```cmd
net user attacker P@ssword123 /add
net localgroup administrators attacker /add
net user attacker /delete
```
Result: EventCodes 4720 (created), 4732 (added to group), 4726 (deleted) all captured and alerted

---

## MITRE ATT&CK Coverage Map

| Tactic | Technique | ID | Detected? |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | ✅ Yes |
| Credential Access | Password Spraying | T1110.003 | ✅ Yes |
| Execution | PowerShell | T1059.001 | ✅ Yes |
| Persistence | Create Account | T1136 | ✅ Yes |
| Defense Evasion | Obfuscated Files or Info | T1027 | ✅ Yes |
| Discovery | Network Service Discovery | T1046 | ✅ Yes |
| Privilege Escalation | Valid Accounts | T1078 | ✅ Yes |
| Initial Access | Valid Accounts | T1078 | ✅ Yes |

---

## Key Commands Reference

### Sysmon Installation (on Windows VMs)
```powershell
# Download Sysmon from Sysinternals
# Download SwiftOnSecurity config from GitHub
# Install with config
sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify Sysmon is running
Get-Service sysmon64

# Check Sysmon logs in Event Viewer
# Path: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```

### Splunk Universal Forwarder (inputs.conf)
```ini
[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Application]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### Splunk Search Examples
```
# All failed logins last 24 hours
index=* EventCode=4625 earliest=-24h | table _time, user, src_ip, host

# Sysmon process creation - all PowerShell
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 Image="*powershell*"

# Account creation events
index=* EventCode=4720 | table _time, user, src_user, host

# All events from the attacker IP
index=* src_ip=192.168.10.60
```

### Ubuntu Server — Splunk Management
```bash
# Start Splunk
sudo /opt/splunk/bin/splunk start

# Stop Splunk
sudo /opt/splunk/bin/splunk stop

# Check Splunk status
sudo /opt/splunk/bin/splunk status

# Enable Splunk to start on boot
sudo /opt/splunk/bin/splunk enable boot-start
```

---

## Troubleshooting Scenarios Practiced

| Issue | Root Cause | Resolution |
|---|---|---|
| Logs not appearing in Splunk | Forwarder not pointing to correct IP/port | Updated outputs.conf with correct Splunk server IP |
| Sysmon events missing | inputs.conf sourcetype typo | Corrected sourcetype name, restarted forwarder |
| Splunk UI not accessible from host | Ubuntu firewall blocking port 8000 | Ran `sudo ufw allow 8000` on Ubuntu |
| Hydra brute force not triggering alerts | Alert threshold set too high | Lowered threshold from 50 to 10 failed logins |
| Kali VM cannot reach DC | Wrong VMware network adapter | Changed Kali adapter from Host-only to NAT |
| Splunk search returning no results | Wrong index name in search | Confirmed index name with `index=*` wildcard first |

---

## Skills Demonstrated

| Skill Category | Specific Skills |
|---|---|
| SIEM Operations | Splunk deployment, search, alerts, dashboards, index management |
| Log Analysis | Windows Security Event Logs, Sysmon telemetry, sourcetype parsing |
| Threat Detection | Alert rule creation, threshold tuning, false positive reduction |
| Incident Response | Attack simulation, detection validation, event timeline reconstruction |
| MITRE ATT&CK | Technique mapping, tactic identification, detection coverage analysis |
| Linux Administration | Ubuntu Server setup, service management, firewall configuration |
| Network Security | Attack simulation, traffic analysis, network event logging |
| Scripting | Splunk SPL (Search Processing Language), PowerShell for automation |
| Documentation | Runbooks, detection playbooks, attack/detection mapping tables |

---

## Screenshots

> Screenshots are included in the `/screenshots` folder of this repository.

- `splunk-dashboard.png` — SOC Overview dashboard with all panels populated
- `brute-force-alert.png` — Splunk alert firing after Hydra attack
- `sysmon-events.png` — Sysmon process creation events in Splunk
- `attack-timeline.png` — Reconstructed attack timeline from log data
- `mitre-coverage.png` — Detection coverage mapped to ATT&CK tactics

---

## Project Phases

| Phase | Project | Status |
|---|---|---|
| Phase 1 | Active Directory Home Lab | ✅ Complete |
| Phase 2 | Splunk SIEM + Attack Detection | ✅ Complete |
| Phase 3 | Azure AD Connect + Hybrid Identity | ✅ Complete |
| Phase 4 | Cloud Security Monitoring (Azure Sentinel) | 📋 Planned |

---

## Resources Used

- [Splunk Free Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)
- [Sysmon — Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Kali Linux](https://www.kali.org/get-kali/)
- [Ubuntu Server 22.04 LTS](https://ubuntu.com/download/server)

---

## About This Project

Built by **Lloyd Barnes** — Systems Administrator | Cloud Security | CompTIA CySA+

- 🔗 LinkedIn: [linkedin.com/in/lloyd-barnes-ii](https://www.linkedin.com/in/lloyd-barnes-ii)
- 🏅 Credly: [credly.com/users/lloyd-barnes.6c44ecd1](https://www.credly.com/users/lloyd-barnes.6c44ecd1)
- 💻 GitHub: [github.com/lbarnes86](https://www.github.com/lbarnes86)
