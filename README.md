# 🕵️‍♂️ Threat Hunt Report: Source Leak

**Date:** April 6, 2026

## 🎯 Scenario

Trigger : Unreleased source code from EmberForge Studios' upcoming title "Neon Shadows" appeared on underground forums. The leaked material includes proprietary game engine components and  unreleased assets. External monitoring flagged the leak within 48 hours of it appearing.

Directive: Investigate the full attack chain. Determine how the attacker gained access, what they stole, how they moved through the environment, and what persistence mechanisms remain. Prioritise scoping the damage for legal and breach notification.

---

## 🖥️ Environment Details

---

## Flag 1 – Environment Access

**Objective**: What is the name of the custom log table containing the investigation data?

**Finding**:  
- **Log Table**: `EmberForgeX_CL`  
--
## Flag 2 – Target Directory

**Objective**: The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?

**Finding**:  
- **Target**: `C:\GameDev`  

**KQL Query**:
```kql
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| project TimeGenerated, Computer, CommandLine_s 
| where CommandLine_s has ".zip"
```

![image](https://github.com/user-attachments/assets/949e28f2-8c38-40a8-babd-fa8c796b8105)
**Notes:** To exfiltrate the source code, the attacker packaged the data into a compressed archive. The first step is identifying the directory from which the data was collected. I filtered for any .zip files that the attacker may have created

---
## Flag 3 – Exfil Destination

**Objective**: The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

**Finding**:  
- **Cloud Storage**: `MEGA`

**KQL Query**:
```kql
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| project TimeGenerated, Computer, CommandLine_s 
| where CommandLine_s has "gamedev.zip"
```

<img width="551" height="23" alt="Flag2" src="https://github.com/user-attachments/assets/171c9f5b-d7aa-455f-b45a-61ea193c2cbe" />

**Notes:** The command shows the compressed archive was exfiltrated using a command-line tool. The mega: destination indicates the data was uploaded to the cloud storage service `MEGA`, which is defined as the remote target in the tool’s configuration.

---
## Flag 4 – Attacker Attribution

**Objective**: Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

**Finding**:  
- **Credentials**: `jwilson.vhr@proton.me`
- **Host Name**: `EC2AMAZ-16V3AU4`

**KQL Query**:
```kql
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Computer == "EC2AMAZ-16V3AU4.emberforge.local"
| project TimeGenerated, Computer, CommandLine_s
| where CommandLine_s has "@"

```

**Notes:** The command line shows the exfiltration tool was run with credentials included. The `--mega-user` flag contains the email used to authenticate to the cloud service. The account used was `jwilson.vhr@proton.me`.


---
## Flag 5 – Domain Compromise Evidence 

**Objective**: This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

**Finding**:  
- **DC**: `EC2AMAZ-EEU3IA2`
- **Database File**: `ntds.dit`
- **Temp File**: `nyMdRNSp.tmp`

**KQL Query**:
```kql
EmberForgeX_CL
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:30) .. datetime(2026-01-30 23:40))
| where CommandLine_s has "copy" 
| project UtcTime_s, Computer, CommandLine_s

```

- **<img width="859" height="79" alt="Flag4" src="https://github.com/user-attachments/assets/96ff1e36-0059-4707-b156-484fedb381fb" />

**Notes:** Via the Domain Controller, the attacker created a shadow copy of a core database filed used by the AD. This file acts as the directories information hierarchy, containing all AD data such as credentials, password hashes, group memberships and security policies. The attacker copied the data into a temp file `nyMdRNSp.tmp`.

---

## <h1>How Did Data Leave?

## Flag 6 – Exfil Tool

**Objective**: A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

**Finding**:  
- **Cloud Sync Tool**: `rclone.exe`

**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:30) .. datetime(2026-01-30 23:40))
| where CommandLine_s has "copy" or CommandLine_s has "gamedev.zip"
| project UtcTime_s, Computer, CommandLine_s

```
<img width="721" height="120" alt="Flag5" src="https://github.com/user-attachments/assets/f87f20ab-f0fa-4ebe-bb6b-43274bdbe71e" />

**Notes:** `rclone.exe` is the cloud sync tool that is being used to copy `gamedev.zip` to the remote cloud provider `mega` 

---

## Flag 7 – Exfil Destination IP

**Objective**: The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

**Finding**:  
- **IP**: `66.203.125.15`

**KQL Query**:
```kql
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:11:28) .. datetime(2026-01-31 00:00))
| project UtcTime_s, Computer, CommandLine_s, process_name_s, EventCode_s, DestinationIp_s
| where process_name_s == "rclone.exe" and EventCode_s == "3"

```
<img width="709" height="109" alt="Flag6" src="https://github.com/user-attachments/assets/6c6d31c3-7afe-4008-b851-ece610e2ae94" />


**Notes:**  Correlation of the exfiltration tool’s process with network events shows that `rclone.exe` sent the stolen data to the IP address `66.203.125.15`

---

## Flag 8 – Attacker Credential Exposure

**Objective**: The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

**Finding**:  
- **Email**: `jwilson.vhr@proton.me`
- **Password**: `Summer2024!`
  

**KQL Query**:
```kql
EmberForgeX_CL 
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:00) .. datetime(2026-01-31 00:00))
| project-reorder UtcTime_s desc
| project-away TimeGenerated
| where CommandLine_s has "rclone"
| project UtcTime_s, CommandLine_s

```

<img width="617" height="64" alt="Flag7" src="https://github.com/user-attachments/assets/4ec2c98b-2357-4675-8cfa-ce88e3ca6b27" />

**Notes:**: The attacker receklessly left their password to `MEGA` in the command line with their email exposed as well.

---

## Flag 9 – Archive Method

**Objective**: Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

**Finding**:  
- **cmdlet**: `Compress-Archive`
  

**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 23:30) .. datetime(2026-01-30 23:40))
| where CommandLine_s has "copy" or CommandLine_s has "gamedev.zip"
| project UtcTime_s, Computer, CommandLine_s

<img width="527" height="82" alt="Flag8" src="https://github.com/user-attachments/assets/16e15b1f-839f-4f90-91ee-4a42a8d2e96e" />

```
**Notes:**: It appears the attacker used Powershell's built in cmdlet, `Compress-Archive`, to compress the data into an archived folder. 

---

## Flag 10 – Staging Server

**Objective**: The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Finding**:  
- **Server Name**: `sync.cloud-endpoint.ne`
  

**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| project-reorder UtcTime_s desc
| project-away TimeGenerated
| project UtcTime_s, CommandLine_s
| where CommandLine_s has_any ("https", "http", "curl")

```

<img width="959" height="284" alt="Flag9" src="https://github.com/user-attachments/assets/d5da204d-abd7-41b2-a1e6-f1cde1407753" />


**Notes:**: Analysis of command line activity shows the attacker downloaded tools from an external staging server using a built-in utility. Multiple commands reference the same server, indicating controlled infrastructure used for tool delivery. The staging server identified is `sync.cloud-endpoint.net`.


---

<H1>Where id it all start?</H1>

## Flag 11 – Malicious File

**Objective**: The incident started with Lisa opening something from her desktop. Find the earliest malicious process creation event on the workstation. A Windows utility was used to load a file that does not belong in a normal user workflow.

**Finding**:  
- **Initial Process Time**: `9:27:03 PM`
- **Workstation**:`EC2AMAZ-B9GHHO6.emberforge.local`
- **Binary File**: `rundll32.exe`
- **DLL File**: `review.dll`
  

**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has ".exe"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer, EventCode_s
```

<img width="743" height="377" alt="Flag10" src="https://github.com/user-attachments/assets/b376fe49-b16d-4d32-ac55-35016ad3b1c5" />


**Notes:** Upon further analysis, it appears the initial malicious process begins at `9:27:03 PM`, where the workstation `EC2AMAZ-B9GHHO6.emberforge.local`, loaded a file that used trusted binaries to conceal its maliciousness. The attacker used `rundll32.exe` to run a DLL file `review.dll` which is the payload containing malicious code. 


---

## Flag 12 – Delivery Vector

**Objective**: Look at the full path of the malicious file. The drive letter is significant. If the file is not on C:, consider how it got there. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

**Finding**:  
- **Malicious File**: `review.dll`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has ".exe"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer, EventCode_s
```

<img width="743" height="377" alt="Flag10" src="https://github.com/user-attachments/assets/b376fe49-b16d-4d32-ac55-35016ad3b1c5" />


**Notes:** The malicious file `review.dll` was executed from the `D:` drive rather than the system’s primary `C:` drive. This indicates the file originated from a mounted virtual drive, such as an ISO or disk image. This would allow the attacker to deliver and execute malicious content more easily because it bypasses certain security controls. 
