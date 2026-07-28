# Tempest — Incident Investigation Report

**Analyst:** Amal Shaji  
**Platform:** TryHackMe SOC Level 1 Capstone  
**Type:** Endpoint Forensics and Network Traffic Analysis  
**Artifacts:** Sysmon Logs, Windows Event Logs, Network Packet Capture  

---

## Task 1 — Preparation

### Overview

Before any investigation begins, the provided 
artifacts must be verified, and the analysis 
environment prepared. This ensures evidence 
integrity before analysis starts, a 
fundamental step in any DFIR engagement.

---

### Artifacts Received

The first step was listing the contents of 
the provided directory to confirm all three artefacts were present and accounted for.

![Directory contents listing](./screenshots/task-1/Preparation-1.png)

| Artefact | Type |
|----------|------|
| capture.pcapng | Network packet capture |
| sysmon.evtx | Sysmon event log |
| Windows Event Logs | Endpoint logs |

---

### Hash Verification

SHA-256 hashes were generated for all three
artifacts using PowerShell's Get-FileHash
command. This confirms the integrity of each 
file, ensuring no tampering has occurred 
since collection and providing a reference 
hash for future verification.

```powershell
Get-FileHash capture.pcapng
Get-FileHash sysmon.evtx
Get-FileHash <windows event log file>
```

![SHA-256 hash of capture.pcapng](./screenshots/task-1/Preparation-2.png)
![SHA-256 hash of sysmon.evtx](./screenshots/task-1/Preparation-3.png)
![SHA-256 hash of Windows Event Log](./screenshots/task-1/Preparation-4.png)

---

### Log Conversion

The Sysmon .evtx file was converted to CSV 
format using EvtxECmd. This makes the log 
data structured and filterable, allowing 
it to be ingested into Timeline Explorer 
for timeline-based analysis.

![EvtxECmd conversion command](./screenshots/task-1/Preparation-5.png)

---

### Timeline Explorer

The converted CSV file was imported into 
Timeline Explorer, providing a chronological 
and filterable view of all Sysmon events 
across the full investigation period. This 
forms the primary analysis interface for 
the endpoint investigation tasks that follow.

![CSV file loaded in Timeline Explorer](./screenshots/task-1/ss6.png)

---

### Skills Applied

- Directory enumeration and artifact
  identification
- SHA-256 hash generation using PowerShell
  Get-FileHash
- Windows Event Log conversion using EvtxECmd
- Timeline construction using Timeline Explorer

---

## Task 2 — Initial Access — Malicious Document

### Scenario

The SOC team flagged a CRITICAL severity alert 
requiring further investigation. The analyst 
confirmed the intrusion originated from a 
malicious document with the following known 
information:

- The malicious document has a .doc extension
- The user downloaded it via chrome.exe
- The document executed a chain of commands
  to attain code execution

---

### Investigation Process

**Step 1 — Identifying the malicious document**

Starting from the known information that the 
document was downloaded via Chrome, I filtered 
Timeline Explorer for chrome.exe activity. 
This returned the malicious document filename
— `free_magicules.doc` — confirming it was 
downloaded through the browser onto the 
compromised machine.

![Chrome.exe download activity in Timeline Explorer](./screenshots/task-2/ss1.png)

---

**Step 2 — Identifying the compromised user 
and machine**

Searching for `free_magicules.doc` in Timeline 
Explorer returned the associated Sysmon events, 
revealing the username and machine name of the 
compromised endpoint. This established the 
scope of the compromise and confirmed which 
account was affected.

![Compromised username and machine name](./screenshots/task-2/ss2.png)

---

**Step 3 — Identifying the Microsoft Word PID**

The malicious document was opened in Microsoft
Word. Filtering Timeline Explorer for Word 
process creation events associated with
`free_magicules.doc` returned the Process ID 
of the Microsoft Word instance that executed 
the document — PID 496. This PID became the 
central pivot point for all subsequent 
investigation steps.

![Microsoft Word PID 496](./screenshots/task-2/ss3.png)

---

**Step 4 — Identifying the malicious domain 
and encoded payload**

Using PID 496 as the pivot, I applied the 
following filters in Timeline Explorer:

- Username: `benimaru`
- Event ID: `22` — DNS Query
- Payload 1: `496`

Event ID 22 in Sysmon captures DNS queries 
made by processes. Filtering on the username, 
PID, and DNS query event type returned the
IPv4 address resolved by the malicious domain 
contacted by the document upon execution.

The same filter also revealed a Base64-encoded 
string present in the malicious payload 
executed by the document. Base64 encoding is 
commonly used by attackers to obfuscate 
commands and evade signature-based detection.

To understand the exploitation technique used 
by the malicious document, I searched for the 
CVE associated with SysWOW64\msdt.exe. This 
returned the specific CVE number and confirmed 
the vulnerability being exploited — providing 
context around the affected software version 
and the nature of the attack.

![DNS query and Base64 encoded payload](./screenshots/task-2/ss4.png)

---

### Tools Used

| Tool | Purpose |
|------|---------|
| Timeline Explorer | Filtering Sysmon events by process, username, and Event ID |
| Sysmon Event ID 22 | DNS query events used to identify malicious domain |
| Internet research | Searched SysWOW64\msdt.exe CVE to identify the vulnerability exploited by the malicious document |

---

### Key Findings

| Finding | Detail | Source |
|---------|--------|--------|
| Malicious document | free_magicules.doc | Timeline Explorer — chrome.exe filter |
| Compromised username | benimaru | Timeline Explorer — document search |
| Compromised machine | Identified from Sysmon events | Timeline Explorer |
| Microsoft Word PID | 496 | Timeline Explorer — process creation |
| Malicious domain IPv4 | Identified via DNS query | Sysmon Event ID 22 |
| Encoded payload | Base64 encoded command string | Sysmon Event ID 22 |
| CVE number | Identified by searching SysWOW64\msdt.exe CVE — confirmed CVE details through internet research | Internet research |

---

### Analyst Notes

The use of PID 496 as a pivot point across
multiple filter combinations was the key
methodology in this task. Rather than searching
broadly across all events, anchoring filters
to the known PID of the Word process that
opened the malicious document significantly
narrowed results and surfaced the relevant
DNS and payload events quickly.

The Base64 encoding of the payload is a
classic obfuscation technique. Encoded
commands pass through many content filters
undetected — decoding them is a standard
step in any document-based malware
investigation.

---

## Task 3 — Initial Access Stage 2

*Coming soon*

---

## Task 4 — C2 Traffic Analysis

*Coming soon*

---

## Task 5 — Discovery

*Coming soon*

---

## Task 6 — Privilege Escalation

*Coming soon*

---

## Task 7 — Persistence

*Coming soon*
