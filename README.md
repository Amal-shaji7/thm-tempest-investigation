# Tempest — SOC Level 1 Capstone Investigation
**Platform:** TryHackMe | **Path:** SOC Level 1  
**Analyst:** Amal Shaji  
**Type:** Endpoint Forensics and Network Traffic Analysis  


---

## Scenario

The Tempest workstation has been compromised.
As an incident responder I was tasked with
analysing three captured artifacts from the
machine to reconstruct the full attack chain
and uncover everything the attacker did from
initial access through to establishing
persistent access.

Three artefacts were provided for analysis:

- Sysmon event logs
- Windows Event Logs
- Network packet capture

---

## Investigation Phases

| Task | Phase | Description |
|------|-------|-------------|
| 1 | Preparation | Tool setup and artifact verification |
| 2 | Initial Access | Identifying the compromised machine and malicious document |
| 3 | Initial Access Stage 2 | Second stage payload and C2 establishment |
| 4 | C2 Traffic Analysis | Network traffic and payload delivery analysis |
| 5 | Discovery | Sensitive file identification and remote access |
| 6 | Privilege Escalation | Privilege abuse and elevated C2 |
| 7 | Persistence | Account creation and persistent access mechanisms |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| EvtxECmd | Converts .evtx Windows Event Log files to CSV |
| Timeline Explorer | Parses and filters CSV logs for timeline analysis |
| SysmonView | Visualises Sysmon logs for process and network events |
| Event Viewer | Native Windows Event Log review |
| Wireshark | Network packet capture analysis |
| VirusTotal | Hash and IOC verification |

---

## Artefacts Analysed

| Artefact | Type | Description |
|----------|------|-------------|
| capture.pcapng | Network | Full packet capture of machine network traffic |
| sysmon.evtx | Endpoint | Sysmon process and network event logs |
| Windows Event Logs | Endpoint | Security, System, and Application event logs |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1566 | Malicious document as initial entry point |
| Execution | T1204 | User executed the malicious document |
| Command and Control | T1071 | C2 communication over application layer protocol |
| Command and Control | T1090 | Reverse proxy tunnelling using Chisel |
| Discovery | T1083 | Sensitive file and directory discovery |
| Discovery | T1057 | Process and privilege enumeration |
| Privilege Escalation | T1134 | Windows privilege abuse for escalation |
| Lateral Movement | T1572 | Protocol tunnelling via Chisel |
| Persistence | T1136 | New local user accounts created |
| Persistence | T1547 | Login-triggered command execution configured |

---

##Repo Structure

thm-tempest-investigation/
├── README.md
├── task-1-preparation/
│   └── README.md
├── task-2-initial-access/
│   └── README.md
├── task-3-initial-access-stage2/
│   └── README.md
├── task-4-c2-traffic/
│   └── README.md
├── task-5-discovery/
│   └── README.md
├── task-6-privilege-escalation/
│   └── README.md
└── task-7-persistence/
    └── README.md

---

## Key Takeaways

- Multi-source correlation was essential,
  no single artifact told the complete story.
- Legitimate tools like Chisel were abused
 to blend malicious traffic with normal
 network activity.
- Encoded payloads and obfuscated commands
 were used at multiple stages to evade
 signature-based detection.
- Privilege escalation through token
 manipulation highlights why monitoring
 specific Windows privileges matters.
- Persistence through account creation
 combined with login-triggered execution
 ensures attacker access survives reboots.

---

*Completed as part of TryHackMe SOC Level 1*  
*Capstone Investigation Series*
