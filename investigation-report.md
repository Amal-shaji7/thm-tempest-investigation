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
Get-FileHash windows.evtx
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

![CSV file loaded in Timeline Explorer](./screenshots/task-1/Preparation-6.png)

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

![Chrome.exe download activity in Timeline Explorer](./screenshots/task-2/initial_access-1.png)

---

**Step 2 — Identifying the compromised user 
and machine**

Searching for `free_magicules.doc` in Timeline 
Explorer returned the associated Sysmon events, 
revealing the username and machine name of the 
compromised endpoint. This established the 
scope of the compromise and confirmed which 
account was affected.

![Compromised username and machine name](./screenshots/task-2/initial_access-2.png)

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

![Microsoft Word PID 496](./screenshots/task-2/initial_access-3.png)

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

![DNS query and Base64 encoded payload](./screenshots/task-2/initial_access-4.png)
![CVE details](./screenshots/task-2/initial_access-5.png)

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

## Task 3 — Initial Access Stage 2

### Overview

Following the initial malicious document execution
a second stage payload was deployed. This task
traces the full Stage 2 execution chain including
payload location, login-triggered execution command,
binary identification, and C2 establishment.

---

### Investigation Process

**Step 1 — Decoding the Base64 Payload**

The Base64-encoded string identified in Task 2
was decoded using CyberChef. Converting the 
encoded string to human-readable text revealed 
the actual command executed by the malicious 
document, providing clear visibility into the
attacker's intentions at this stage of the 
attack chain.

![CyberChef Base64 decode](./screenshots/task-3/ss1.png)

---

**Step 2 — Finding the Stage 2 Payload Path**

To identify where the Stage 2 payload was
written on the filesystem I applied the
following filters in Timeline Explorer:

- Username: `benimaru`
- Event ID: `11` — File Create
- Payload data: `startup`

Sysmon Event ID 11 captures file creation
events. Filtering on the username and the
startup keyword returned the full target
path where the Stage 2 payload was written
on the compromised machine.

![Stage 2 payload path — Event ID 11 filter](./screenshots/task-3/ss2.png)

---

**Step 3 — Identifying the Login-Triggered
Execution Command**

To find the command configured to execute
automatically upon user login I applied the
following filters in Timeline Explorer:

- Username: `benimaru`
- Event ID: `1` — Process Create
- Payload 4: `explorer`

Event ID 1 captures process creation events.
Filtering on explorer as the parent process
is significant because explorer.exe is the
Windows shell — processes launched at login
are typically spawned as children of
explorer.exe. This filter returned the full
command configured to execute automatically
whenever the compromised user logged in.

![Login-triggered execution command](./screenshots/task-3/ss3.png)

---

**Step 4 — Finding the SHA-256 Hash of the
Stage 2 Binary**

The payload path identified in Step 2 revealed
the Stage 2 binary location:

```
C:\Users\Public\Downloads\first.exe
```

Using this path I applied the following
filters in Timeline Explorer:

- Username: `benimaru`
- Executable info: `C:\Users\Public\Downloads\first.exe`

This returned the SHA-256 hash of the
malicious binary — confirming its identity
and providing an IOC for threat intelligence
lookups.

![SHA-256 hash of Stage 2 binary](./screenshots/task-3/ss4.png)

---

**Step 5 — Identifying the C2 Domain and Port**

Switching to Wireshark I analysed the network
packet capture to identify the C2 domain and
port used by the Stage 2 binary to communicate
with the attacker's infrastructure.

Network traffic analysis revealed:

- **C2 Domain:** resolvecyber[.]xyz
- **Port:** 80

The use of port 80 is a deliberate evasion
technique. HTTP traffic on port 80 blends with
normal web browsing traffic making it
significantly harder to detect through
port-based network monitoring alone. Behavioural
analysis and content inspection are required
to identify malicious HTTP traffic of this type.

![C2 domain and port in Wireshark](./screenshots/task-3/ss5.png)

---

### Tools Used

| Tool | Purpose |
|------|---------|
| CyberChef | Base64 decoding of obfuscated payload |
| Timeline Explorer | Filtering Sysmon events by Event ID, username, and payload data |
| Sysmon Event ID 11 | File creation events — identifying Stage 2 payload path |
| Sysmon Event ID 1 | Process creation events — identifying login-triggered command |
| Wireshark | Network traffic analysis — C2 domain and port identification |

---

### Key Findings

| Finding | Detail | Source |
|---------|--------|--------|
| Decoded payload | Human-readable attacker command | CyberChef |
| Stage 2 payload path | Full filesystem path of dropped binary | Sysmon Event ID 11 |
| Login-triggered command | Full command executing on user login | Sysmon Event ID 1 |
| Stage 2 binary | first.exe | Sysmon file events |
| Stage 2 binary SHA-256 | Confirmed hash of malicious binary | Timeline Explorer |
| C2 domain | resolvecyber[.]xyz | Wireshark |
| C2 port | 80 | Wireshark |

---

### Analyst Notes

The choice of port 80 for C2 communication is
a deliberate and common attacker technique.
By routing malicious traffic over standard
HTTP the attacker blends into normal network
activity. This highlights why deep packet
inspection and behavioural analysis are
essential alongside traditional port-based
firewall rules.

Filtering on explorer.exe as the parent
process for Event ID 1 was the key pivot
in identifying the login-triggered command.
Understanding Windows process hierarchy is
fundamental to efficient Sysmon log
investigation — knowing which processes
spawn which children significantly narrows
filter combinations and surfaces relevant
events faster.

---

## Task 4 — C2 Traffic Analysis



### Overview

This task focused entirely on network traffic
analysis using Wireshark and CyberChef to
identify the malicious payload delivery URL,
C2 communication patterns, encoding methods,
and the programming language used to compile
the malicious binary.

---

### Investigation Process

**Step 1 — Finding the Malicious Payload URL**

Using Wireshark I applied the filter:

```
http
```

This filtered all HTTP traffic in the packet
capture. Scanning through the results I
identified a packet containing a reference
to `free_magicules.doc` - the malicious
document identified in Task 2. This packet
confirmed the document was delivered over
HTTP and provided the starting point for
identifying the full delivery URL.

![HTTP filter showing free_magicules.doc packet](./screenshots/task-4/ss1.png)

---

**Step 2 — Finding the Full Delivery URL**

To find the full URL used to deliver the
malicious document I applied the following
Wireshark filter:

```
http.host
```

Filtering on the host associated with the
document delivery returned the full URL
including the host `phishteam.xyz` and
confirmed the complete delivery path
ending with `index.html`.

![http.host filter results](./screenshots/task-4/ss2.png)

![Full URL with index.html confirmed](./screenshots/task-4/ss3.png)

---

**Step 3 — Identifying C2 Encoding and
Communication Parameters**

To investigate the C2 communication from
the Stage 2 binary I applied the following
Wireshark filter:

```
http contains "resolvecyber"
```

This filtered all HTTP traffic containing
references to `resolvecyber` — the C2
domain identified in Task 3. Examining
the resulting GET request revealed:

- **Encoding used:** Base64 — the attacker
  encoded C2 commands in Base64 to obfuscate
  communication and evade content-based
  detection
- **Parameter used to execute commands:** `q`
- **URL used by binary:** `/9ab62b5`
- **HTTP method:** GET

![resolvecyber HTTP GET request](./screenshots/task-4/ss4.png)

---

**Step 4 — Identifying the Programming Language**

To gather more context about the malicious
binary I right-clicked the relevant packet
and selected **Follow TCP Stream**. Examining
the full TCP stream content revealed that
the binary was compiled using **Nim** — a
systems programming language increasingly
used by threat actors due to its ability
to produce small, efficient executables
that are less commonly detected by
security tools.

![TCP stream revealing Nim as programming language](./screenshots/task-4/ss5.png)

---

**Step 5 — Decoding the Encoded C2 Command**

The Base64 encoded command found in the
C2 GET request was extracted and decoded
using CyberChef. The decoded output revealed
the command being sent by the attacker
through the C2 channel was:

```
whoami - benimaru
```

This is a standard attacker reconnaissance
command used to confirm the identity and
privilege level of the compromised account
immediately after establishing C2
communication.

![CyberChef decoding Base64 command to whoami](./screenshots/task-4/ss6.png)

---

### Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | HTTP traffic filtering and TCP stream analysis |
| CyberChef | Base64 decoding of encoded C2 command |

---

### Key Findings

| Finding | Detail | Source |
|---------|--------|--------|
| Malicious payload delivery host | phishteam.xyz | Wireshark http.host filter |
| Full delivery URL | phishteam.xyz/index.html | Wireshark HTTP filter |
| C2 encoding method | Base64 | Wireshark resolvecyber filter |
| C2 command parameter | q | Wireshark GET request |
| C2 URL path | /9ab62b5 | Wireshark GET request |
| HTTP method | GET | Wireshark HTTP filter |
| Binary programming language | Nim | Wireshark Follow TCP Stream |
| Decoded C2 command | whoami | CyberChef |

---

### Analyst Notes

The use of Base64 encoding for C2 commands
over HTTP GET requests on port 80 is a
deliberate layered evasion technique. The
attacker combined three evasion methods
simultaneously — standard HTTP protocol,
common port 80, and encoded payloads — to
blend malicious traffic with normal web
browsing activity.

The `whoami` command as the first C2
instruction is consistent with standard
attacker post-exploitation behaviour.
Confirming the identity and privilege level
of the compromised account is the first
step before deciding which escalation or
lateral movement technique to pursue next.

The identification of Nim as the compilation
language is a significant threat intelligence
finding. Nim-compiled binaries are
increasingly used by threat actors because
they produce executables with lower detection
rates against traditional antivirus and EDR
solutions compared to more commonly flagged
languages like C or PowerShell.

---

## Task 5 — Discovery

### Overview

With C2 communication established the attacker
conducted internal discovery on the compromised
machine. This task traces how the attacker
identified a sensitive file and its password,
discovered a listening port providing remote
shell access, established a reverse proxy
using Chisel, and authenticated to the machine
using a specific Windows service.

---

### Investigation Process

**Step 1 — Finding the Sensitive File Password**

Returning to Wireshark I applied the following
combined filter to isolate C2 GET requests
to the resolvecyber domain:

```
http.host == resolvecyber.xyz && http.request.method == "GET"
```

This returned a number of packets containing
Base64 encoded commands sent through the C2
channel. Each packet was extracted and decoded 
individually using CyberChef. Working through
the decoded outputs one by one I identified
a specific packet whose decoded content
contained a password — `infernotempest` —
revealing the password of the sensitive file
discovered by the attacker on the compromised
machine.

![Wireshark filter showing resolvecyber GET requests](./screenshots/task-5/ss1.png)

![CyberChef decode revealing password infernotempest](./screenshots/task-5/ss2.png)

---

**Step 2 — Identifying the Listening Port**

Continuing through the remaining encoded
packets from the same Wireshark filter I
identified another packet whose decoded
content revealed a `netstat` command output.
The decoded netstat results contained a list
of active network connections, process IDs,
and listening ports on the compromised machine.

Analysing the output I identified the
listening port providing remote shell access
to the machine — PID 5985 — confirming an
active listening service the attacker could
use for remote access.

![Wireshark packet containing encoded netstat output](./screenshots/task-5/ss3.png)

![CyberChef decode revealing netstat results and PID 5985](./screenshots/task-5/ss4.png)

---

**Step 3 — Finding the Reverse Proxy Command
and SHA-256 Hash**

Returning to Timeline Explorer I searched for
the reverse proxy activity. Filtering for the
SOCKS reverse proxy command returned the full
command executed by the attacker to establish
the Chisel reverse proxy connection — providing
complete visibility into how the attacker
tunnelled their C2 traffic through the
compromised machine.

The same filter also returned the SHA-256
hash of the Chisel binary directly from the
Sysmon event data.

![Timeline Explorer reverse proxy SOCKS command](./screenshots/task-5/ss5.png)

![SHA-256 hash of Chisel binary in Timeline Explorer](./screenshots/task-5/ss6.png)

---

**Step 4 — Identifying the Tool Using VirusTotal**

The SHA-256 hash of the binary was submitted
to VirusTotal for threat intelligence lookup.
The results confirmed the binary as **Chisel**
— a legitimate open-source TCP and UDP
tunnelling tool written in Go that is
increasingly abused by threat actors to
establish reverse proxy connections and
tunnel C2 traffic through compromised
endpoints.

![VirusTotal results identifying Chisel](./screenshots/task-5/ss7.png)

---

**Step 5 — Identifying the Authentication Service**

Returning to Timeline Explorer I searched for
`wsmprovhost` — the Windows Remote Management
(WinRM) provider host process. This process
is associated with PowerShell remoting and
WinRM-based authentication.

The search confirmed that `wsmprovhost.exe`
was the service used by the attacker to
authenticate to the compromised machine —
consistent with the listening port 5985
identified in Step 2, which is the default
WinRM HTTP port.

![wsmprovhost authentication service in Timeline Explorer](./screenshots/task-5/ss8.png)

---

### Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | HTTP GET request filtering to isolate C2 commands |
| CyberChef | Base64 decoding of encoded C2 command outputs |
| Timeline Explorer | Reverse proxy command and hash identification |
| VirusTotal | Binary hash lookup confirming Chisel |

---

### Key Findings

| Finding | Detail | Source |
|---------|--------|--------|
| Sensitive file password | infernotempest | Wireshark and CyberChef |
| Listening port | 5985 | Wireshark netstat decode via CyberChef |
| Reverse proxy command | Full SOCKS command recovered | Timeline Explorer |
| Chisel binary SHA-256 | Confirmed hash | Timeline Explorer |
| Tool name | Chisel | VirusTotal |
| Authentication service | wsmprovhost — WinRM | Timeline Explorer |

---

### Analyst Notes

The methodology of iterating through multiple
Base64 encoded C2 packets and decoding each
one individually was time consuming but
essential. The attacker sent multiple commands
through the C2 channel and the sensitive
findings, the file password and the netstat
output were not immediately obvious without
working through all of them systematically.

The identification of port `5985` alongside
wsmprovhost.exe is significant. Port `5985`
is the default WinRM HTTP port used for
PowerShell remoting. The attacker leveraged
WinRM as their authentication mechanism 
a legitimate Windows service used to avoid
raising suspicion. This is another example
of living-off-the-land technique where
built-in Windows services are abused for
malicious purposes.

The use of Chisel for reverse proxy
establishment is consistent with real-world
threat actor TTPs. By tunnelling C2 traffic
through a legitimate looking TCP connection, 
the attacker significantly reduces the 
likelihood of detection through standard 
network monitoring. Detection requires
behavioural analysis — specifically looking
for unusual outbound connections from
unexpected processes.

---

## Task 6 — Privilege Escalation

*Coming soon*

---

## Task 7 — Persistence

*Coming soon*
