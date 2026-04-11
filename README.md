# Threat Hunt Report: EmberForge Source Leak

**Date:** April 6, 2026

## 🎯 Scenario

Trigger : Unreleased source code from EmberForge Studios' upcoming title "Neon Shadows" appeared on underground forums. The leaked material includes proprietary game engine components and  unreleased assets. External monitoring flagged the leak within 48 hours of it appearing.

Directive: Investigate the full attack chain. Determine how the attacker gained access, what they stole, how they moved through the environment, and what persistence mechanisms remain. Prioritise scoping the damage for legal and breach notification.

---

## Platform and Languages 

 • Windows 11 VM
 
 • Microsoft Sentinel SIEM
 
 • Kusto Query Language (KQL)


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

---

## Flag 13 – Compromised User

**Objective**: The User field in process creation events tells you which account executed the payload. This is patient zero.

**Finding**:  
- **Patient Zero Username**: `lmartin`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27) .. datetime(2026-01-31 00:00))
| where CommandLine_s has ".exe"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer, user_s
```

**Notes:** 'review.dll' is the payload file that was executed using the user profile 'lmartin'


---

## Flag 14 – Execution Chain

**Objective**: Every process has a parent, and that parent has a parent. Trace the full execution chain from the user action through to the malicious file being loaded.

**Finding**:  
- **Processes**: `explorer.exe > rundll32.exe > review.dll`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:27) .. datetime(2026-01-31 00:00))
| where CommandLine_s has ".exe"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="609" height="94" alt="Flag12" src="https://github.com/user-attachments/assets/62eab281-1be7-4b67-895d-561b4cca1464" />

**Notes:** Via the File Explorer system on the windows machine, tha payload was executed using the trusted `runll32.exe` binary.

---

## Flag 15 – Delivery Unpacking

**Objective**: Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile. This extraction step came before the DLL execution.

**Finding**:  
- **ISO:** `EmberForge_Review`
- **Compressed Archive Path:** `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 00:00) .. datetime(2026-01-30 21:27))
| where CommandLine_s has "7-Zip"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer, process_name_s, process_path_s, 

```

<img width="709" height="150" alt="Flag14" src="https://github.com/user-attachments/assets/d11940ac-fb51-4d32-a3e6-83c665950e4d" />

**Notes:** Prior to the execution of the malicious payload, Lisa unsuspectally opened a zipped folder whose contents masqueraded as a EmberForge project review file, but was really an ISO with `review.dll` inside it.

---
<h1>What Ran On The Workstation?</h1>

## Flag 16 – Dropped Payload

**Objective**: Shortly after the initial DLL execution, a new executable appeared in a world-writable directory on the workstation. This became the attacker's primary tool for the rest of the operation.

**Finding**:  
- **Executable Path:** `C:\Users\Public\update.exe`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("Temp", "Public", "ProgramData")
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s

```

<img width="532" height="86" alt="Flag15" src="https://github.com/user-attachments/assets/08fbf129-88e9-44af-aecd-1ba34a2db896" />



**Notes:** Shortly after the payloads execution at `9:37:16` there is a task that’s been created to appear as `WindowsUpdate` and scheduled to trigger whenever the system starts up with system privileges. This is highly suspicious because it allows this specific file to remain persistent whenever the machine is online.

---

## Flag 17 – C2 Domain

**Objective**: The malware needs to communicate with the attacker. Sysmon EventCode 22 captures every DNS query a process makes. The domain will look designed to blend in with legitimate cloud traffic.

**Finding**:  
- **Domain:** `cdn.cloud-endpoint.net`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22" and process_exec_s has_any ("update.exe", "rundll32.exe")
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, QueryName_s

```

<img width="1193" height="675" alt="image" src="https://github.com/user-attachments/assets/8424ac02-232a-4c13-ae01-efc22aae0f7d" />

---

## Flag 18 – Primary C2 IP

**Objective**: DNS queries resolve domains to IP addresses. The QueryResults field inside the EventCode 22 raw XML contains the resolved IPs.

**Finding**:  
- **IP:** `104.21.30.237`
  
**KQL Query**:
```kql
	EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22" and process_exec_s has_any ("update.exe", "rundll32.exe")
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, QueryName_s, QueryResults_s

```
<img width="523" height="110" alt="image" src="https://github.com/user-attachments/assets/4783d2f0-b638-4e80-ae59-22d506c1bbce" />

---

## Flag 19 – Injection Chain

**Objective**: The attacker injected code from one process into another to hide. Sysmon EventCode 8 (CreateRemoteThread) captures this. Trace the injection chain.

**Finding**:  
- **Chain:** rundll32.exe > notepad.exe
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, SourceImage_s, SourceUser_s, TargetImage_s, TargetUser_s


```
<img width="1340" height="302" alt="image" src="https://github.com/user-attachments/assets/aee9be7f-0e10-4e84-adf6-a9609c8ad010" />

**Notes:** The attacker injected code from `rundll32.exe` into `notepad.exe` to hide malicious activity within a legitimate process.

<h1>How Did They Elevate?</h1>

## Flag 20 – UAC Bypass Binary

**Objective**: Certain Windows executables are trusted to auto-elevate without a UAC prompt. Attackers hijack what these binaries execute via registry modifications. Look for registry changes (EventCode 13) followed immediately by a trusted binary execution.

**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, EventType_s, TargetObject_s, object_path_s, registry_hive_s, registry_path_s, registry_key_name_s, Details_s, file_name_s

EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:38:00) .. datetime(2026-01-30 21:40:00))
| where EventCode_s == "1"  // Look for Process Creation
| project TimeCreated_t, CommandLine_s, ParentImage_s

```
<img width="2203" height="666" alt="image" src="https://github.com/user-attachments/assets/e294a583-8c1f-475f-be45-7ecede7c8f90" />


<img width="508" height="76" alt="image" src="https://github.com/user-attachments/assets/caba74b6-d0a5-4327-bfc9-69e354b054f1" />


**Notes:** At `9:38 PM` you can see the the registry changes in the first screenshot followed by `rundll32.exe` being executed shortly after. Registry modifications were followed by execution of a trusted Windows binary, indicating a UAC bypass technique to gain elevated privileges without user prompts.

---

## Flag 21 – Registry Bypass Enabler

**Objective**: The UAC bypass works by creating a specific registry value that redirects execution. Two modifications were made in quick succession. One set the payload path. The other enables the hijack. What is that value name?

**Finding**:  
- **Value:** DelegateExecute
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:38:00) .. datetime(2026-01-30 21:40:00))
| where EventCode_s == "1"  // Look for Process Creation
| project TimeCreated_t, CommandLine_s, ParentImage_s

```
<img width="508" height="76" alt="image" src="https://github.com/user-attachments/assets/caba74b6-d0a5-4327-bfc9-69e354b054f1" />

**Notes:** The DelegateExecute registry value was used to hijack execution flow, enabling the UAC bypass.

---

## Flag 22 – Stable Injection Chain

**Objective**: After the UAC bypass, the elevated beacon performed a second injection for long-term stability. The source process was different from the first injection, and the target was running in a completely different security context.

**Finding**:  
- **Processes**: `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, SourceImage_s, SourceUser_s, TargetImage_s, TargetUser_s

```

<img width="700" height="119" alt="Flag21" src="https://github.com/user-attachments/assets/fc09fb3c-da7d-4e50-a237-930868f4a4f3" />

**Notes:** The attacker performed a second injection of their code from `C:\Users\Public\update.exe` into `NT AUTHORITY\SYSTEM`, a highly privileged account used by the Windows OS. 

## Flag 23 – Credential Dumping Process

**Objective**: LSASS holds credentials for every logged-in user. The attacker dumped its memory to disk. The dumping tool used direct syscalls to bypass API monitoring. You will NOT find ProcessAccess events (EventCode 10) for LSASS. What process created the dump file?
  
**KQL Query**:
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:24:04) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| sort by UtcTime_s asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, SourceImage_s, SourceUser_s, TargetImage_s, TargetUser_s

```

<img width="700" height="119" alt="Flag21" src="https://github.com/user-attachments/assets/fc09fb3c-da7d-4e50-a237-930868f4a4f3" />

**Notes:**

---

## Flag 24 – Dump Location

**Objective**: You identified the process. Now find where it wrote the output. File creation events (EventCode 11) track every file written to disk. Where was the credential dump written?

**Finding**:  
- **Path**: `C:\Windows\System32\lsass.dmp`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11" and process_exec_s has "update.exe"
| where TargetFilename_s has_any (".dmp", ".DMP")
| sort by TimeCreated_t asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, TargetFilename_s, User_s, process_exec_s

```

<img width="553" height="129" alt="Flag23" src="https://github.com/user-attachments/assets/ccf1e7ae-3ef6-4bcc-92ba-d701450a16c6" />


**Notes:** The attacker performed a memory dump using `update.exe` and the output of that dump has been identified to be written to the path `C:\Windows\System32\lsass.dmp`. 

<h1>What Did They Enumerate?</h1>

## Flag 25 – User Enumeration

**Objective**: The first command in the discovery sequence queries all user accounts in the domain.

**Finding**:  
- **Command**: `net user /domain`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any("net", "user")
| sort by TimeCreated_t asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="425" height="77" alt="Flag24" src="https://github.com/user-attachments/assets/2c91c2ea-044b-44d2-8966-cc899db285f0" />


**Notes:** The attacker used the `net` command to get a quick list of user accounts on the domain.  

---

## Flag 26 – Privilege Enumeration

**Objective**: Immediately after listing users, the attacker queried a specific group to identify who has the highest level of access.

**Finding**:  
- **Command**: `net group "Domain Groups" /domain`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any("net", "group")
| sort by TimeCreated_t asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer


```

<img width="570" height="76" alt="Flag25" src="https://github.com/user-attachments/assets/04351196-fcd1-4d7b-a170-20628fdb0bc4" />

**Notes:** The attacker used the `net` command to get a list of the accounts with admin privileges 

## Flag 27 – Infrastructure Mapping

**Objective**: The final discovery command locates critical infrastructure. The attacker needs to know where to go next.

**Finding**:  
- **Command**: `nltest /dclist:emberforge.local`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any("net", "group", "nltest")
| sort by TimeCreated_t asc
| project-away TimeGenerated
| project-reorder TimeCreated_t
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="506" height="70" alt="image" src="https://github.com/user-attachments/assets/7528660b-1184-4faf-95d2-13885fe9f133" />

**Notes:** The attacker used nltest to identify domain controllers and map critical infrastructure.

---

<h1>How Did They Spread?</h1>

## Flag 28 – Tool Staging Share

**Objective**: Before moving laterally, the attacker set up the workstation as a distribution point. A network share was created.

**Finding**:  
- **Command**: cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"
  
**KQL Query**:
```kql
EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 22:14:42.919) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has "share"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, host_s, dest_s


```

<img width="1314" height="292" alt="image" src="https://github.com/user-attachments/assets/a92408ce-a016-42c3-b574-fdfd3d791e04" />

**Notes:** A network share was created to distribute tools across systems, preparing for lateral movement.

---

## Flag 29 – Firewall Manipulation 

**Objective**: Before moving laterally, the attacker set up the workstation as a distribution point. A network share was created.

**Finding**:  
- **Rule**: `netsh advfirewall`
- **Name**: `SMB`
- **Port:**: `445'
  
**KQL Query**:
```kql
EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 22:14:42.919) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has "firewall"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, host_s, dest_s

```

<img width="613" height="119" alt="Flag28" src="https://github.com/user-attachments/assets/df12d115-9a71-4e0f-9b8b-c5e578ce86d4" />

**Notes:** Analysis shows the attacker modified the system firewall to allow inbound connections required for lateral movement. A new rule was created using `netsh advfirewall`, with the name `SMB`, to permit traffic over `TCP port 445`.

---

## Flag 30 – Port-Escalation Parent

**Objective**: After the beacon migrated to a SYSTEM process, all subsequent attacker commands on the workstation were executed as children of that process. Look at the parent process of the lateral movement commands (share creation, file copies, firewall changes).

**Finding**:  
- **SYSTEM Process**: `spoolsv.exe`
  
**KQL Query**:
```kql
EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 22:14:42.919) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has_any("netsh", "net", "nltest", "copy")
    | where host_s  == "EC2AMAZ-B9GHHO6"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, host_s, dest_s, parent_process_name_s

```

<img width="720" height="227" alt="Flag29" src="https://github.com/user-attachments/assets/0bede355-178f-47d7-922f-fac286a72174" />

**Notes:** Analysis shows that after initial compromise, the attacker’s beacon migrated into the SYSTEM process `spoolsv.exe`. Subsequent lateral movement activity, including share creation, file transfers, and firewall modifications, was executed as child processes of `spoolsv.exe`, indicating the attacker was operating with elevated privileges.

---

## Flag 31 – Beacon Distribution

**Objective**: The attacker pushed their primary tool to the server via Windows admin shares (C$). What was the full command?

**Finding**:  
- **Full Command**: `cmd.exe /c copy C:\Users\Public\update.exe\\10.1.57.66\C$\Users\Public\update.exe`
  
**KQL Query**:
```kql
 EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 22:14:42.919) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has_any("netsh", "net", "nltest", "copy")
    | where host_s  == "EC2AMAZ-B9GHHO6"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, host_s, dest_s, parent_process_name_s

```

<img width="698" height="130" alt="Flag30" src="https://github.com/user-attachments/assets/6d4452a8-6e77-48ef-95e9-6a1534667042" />

**Notes:** Analysis shows the attacker used Windows administrative shares (C$) to transfer their primary tool to a remote server. 

---

## Flag 32 – LOLBin Tool Staging

**Objective**: On the server, a built-in Windows utility was abused to download tools from the attacker's staging infrastructure. What utility was used, and what was the full URL it downloaded from?

**Finding**:  
- **URL**: `http://sync.cloud-endpoint.net:8080/update.exe`
- **Utility Tool:** certutil.exe
  
**KQL Query**:
```kql
 EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has "http" and CommandLine_s has "sync.cloud-endpoint.net"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, Computer, User_s, src_ip_s, parent_process_exec_s

```

<img width="1232" height="266" alt="Flag31" src="https://github.com/user-attachments/assets/9eb8fbd9-df84-4b27-86f1-ed96010ba148" />


**Notes:** Analysis shows the attacker used Windows administrative shares (C$) to transfer their primary tool to a remote server. 

---

## Flag 33 – Remote Execution Evidence

**Objective**: Now look at the server. The attacker used a remote execution technique that creates temporary Windows services with random names. These appear in EventCode 7045 in Raw_s.

**Finding**:  
- **ServiceName**: `MzLblBFm
  
**KQL Query**:
```kql
 EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where Computer has "16V3AU4" and EventCode_s == "7045"
| parse Raw_s with * "Data Name='ServiceName'>" ServiceName "</Data>" * "Data Name='ImagePath'>" ImagePath "</Data>" *
| project ServiceName, ImagePath

```

<img width="1138" height="278" alt="Flag32 1" src="https://github.com/user-attachments/assets/71123723-1886-4935-824b-e9a0e0ca26ae" />

**Notes:** A temporary service with a random name was created, indicating remote execution via service creation.

---

## Flag 34 – First Command On Server

**Objective**: The remote execution technique redirects command output to temporary files. The very first attacker command on any newly compromised host is almost always the same.

**Finding**:  
- **Command**: `whoami`
  
**KQL Query**:
```kql
 EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 21:00:00) .. datetime(2026-01-31 00:00))
    | where EventCode_s == "1"
    | where CommandLine_s has "Windows\\Temp"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, Computer
```

<img width="566" height="95" alt="Flag32" src="https://github.com/user-attachments/assets/72320e79-bd9b-4231-b8f0-1b17dce52801" /> 

**Notes:** The attacker ran whoami to confirm access level on the newly compromised server.

---

## Flag 35 – Failed Lateral Movement

**Objective**: The attacker's first lateral movement method was unreliable. Authentication logs on the server show repeated failures from an internal host. Examine EventCode 4625.

**Finding**:  
- **Authenteication Package Name**: `NTLM`
- **IP**: 10.1.173.145
  
**KQL Query**:
```kql
 EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where Computer has "16V3AU4" and EventCode_s == "4625"
| parse Raw_s with * "Data Name='AuthenticationPackageName'>" AuthenticationPackageName "</Data>" * "Data Name='IpAddress'>" IpAddress "</Data>" *
| project AuthenticationPackageName, IpAddress

```

<img width="476" height="276" alt="Flag34" src="https://github.com/user-attachments/assets/62f87093-b632-442a-a63b-2a813618e846" />

**Notes:** Multiple failed NTLM authentication attempts show the attacker initially struggled to move laterally.

---

<h1>Did They Own The Domain?</h1>

## Flag 36 – DC Arrival and Credential Extraction

**Objective**: The attacker reached the Domain Controller and immediately began working towards the AD database. Trace the first command and the extraction tool.

**Finding**:  
- **Extraction Tool**: `vssadmin`
- **First Command**: `whoami`

**KQL Query**:
```kql
 EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where Computer has "16V3AU4" and EventCode_s == "4625"
| parse Raw_s with * "Data Name='AuthenticationPackageName'>" AuthenticationPackageName "</Data>" * "Data Name='IpAddress'>" IpAddress "</Data>" *
| project AuthenticationPackageName, IpAddress

```

<img width="2326" height="627" alt="image" src="https://github.com/user-attachments/assets/46efa7b4-d024-4458-a829-10842e63fde7" />

**Notes**: Upon reaching the Domain Controller, the attacker accessed and extracted the Active Directory database `ntds.dit` using volume shadow copy techniques.


---

## Flag 37 – Backdoor Account

**Objective**: After extracting the database, the attacker created a new account designed to blend in with legitimate service accounts.

**Finding**:  
- **Account**: `svc_backup`
  
**KQL Query**:
```kql
 EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "net user"
| project TimeCreated_t, CommandLine_s, Computer
```

<img width="902" height="187" alt="Flag36" src="https://github.com/user-attachments/assets/08a82cfc-f1ee-4ef0-a9d5-0574fb08de3d" />

**Notes:** The attacker created a new account `svc_backup` to maintain access while blending in with legitimate service accounts.

---

## Flag 38 – Backdoor Credentials

**Objective**: The account creation command included the password as a command line argument. Terrible OPSEC, but captured permanently in your logs.

**Finding**:  
- **Password**: `P@ssw0rd123!`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "net user"
| project TimeCreated_t, CommandLine_s, Computer
```
<img width="902" height="187" alt="Flag36" src="https://github.com/user-attachments/assets/08a82cfc-f1ee-4ef0-a9d5-0574fb08de3d" />

**Notes:** The account password was exposed in plaintext within the command line, revealing poor operational security.

---

## Flag 39 – Privilege Assignment

**Objective**: Creating an account is not enough. The attacker ran a second command to give it elevated privileges.

**Finding**:  
- **Command**: `Domain Admins`
  
**KQL Query**:
```kql
EmberForgeX_CL
    | where TimeCreated_t  between (datetime(2026-01-30 22:14:42.919) .. datetime(2026-01-31 00:00))
    | where CommandLine_s has "net group"
    | sort by TimeCreated_t asc
    | project-away TimeGenerated
    | project-reorder TimeCreated_t
    | project TimeCreated_t, CommandLine_s, host_s, dest_s
```

<img width="1247" height="189" alt="image" src="https://github.com/user-attachments/assets/7925024d-bcdc-468a-9562-c4cdb31cb6d4" />

**Notes:** The attacker added the backdoor account to the `Domain Admins` group to gain full control over the domain.

---

## Flag 40 – Exposed Credential

**Objective**: The attacker needed to map a network drive on the DC to access tools. The drive mapping command included authentication credentials in plain text.

**Finding**:  
- **Password**: `EmberForge2024!`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t > todatetime('2026-01-30T23:38:11.7874159Z')
| where CommandLine_s has "net use"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="875" height="108" alt="Flag39" src="https://github.com/user-attachments/assets/c1bf20fd-020d-488e-aa0e-3d29d8602ba7" />

---

<h1>Can They Come Back?</h1>

## Flag 41 – Scheduled Task

**Objective**: The attacker created a scheduled task to ensure their payload survives reboots. The name was chosen to look legitimate.

**Finding**:  
- **Task Name:** `WindowsUpdate`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeCreated_t > todatetime('2026-01-30T23:38:11.7874159Z')
| where CommandLine_s has "onstart /ru"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="902" height="175" alt="Task40" src="https://github.com/user-attachments/assets/ed8dd217-ac61-4cbb-87dd-23489644af33" />

**Notes:** The commandline contains the task the attacker wrote on the machine so that the payload will continue running upon the machine being rebooted.

---

## Flag 42 – Remote Access Tool

**Objective**: A legitimate remote management application was silently installed for unattended access.

**Finding**:  
- **Task Name:** `AnyDesk`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "--silent"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="916" height="320" alt="Flag41" src="https://github.com/user-attachments/assets/47ccf57b-6543-4161-b63e-96f5332ec6c8" />

**Notes:** The silent paramter will install the application in the background. 

---

## Flag 43 – Remote Access Configuration

**Objective**: The attacker read and modified the remote access tool's configuration file. The commands reveal its full path.

**Finding**:  
- **Path:** `C:\ProgramData\AnyDesk\system.conf`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "AnyDesk"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="364" height="71" alt="Task42" src="https://github.com/user-attachments/assets/91c78a6a-91c1-4da4-b650-dc79c41fcc6f" />

**Notes**: The attacker accessed and modified the `AnyDesk` configuration file to maintain control.

---

## Flag 44 – Anti-Forensics Tools

**Objective**: The attacker read and modified the remote access tool's configuration file. The commands reveal its full path.

**Finding**:  
- **Command:** `wevtutil`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "wevtutil"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="863" height="317" alt="Task43" src="https://github.com/user-attachments/assets/22758f8d-a05a-4c9d-bf0a-b32f64b733e5" />

**Notes**: The attacker used `wevtutil` to manipulate or clear Windows event logs and hide activity.

---

## Flag 45 – Cleared Logs

**Objective**: The attacker cleared more than one event log. Each clearing command targets a specific log by name. What two logs were cleared?

**Finding**:  
- **Log Names:** `System, Security`
  
**KQL Query**:
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-15) .. now())
| where CommandLine_s has "wevtutil"
| project TimeCreated_t, CommandLine_s, Computer

```

<img width="863" height="317" alt="Task43" src="https://github.com/user-attachments/assets/22758f8d-a05a-4c9d-bf0a-b32f64b733e5" />


**Notes:** The attacker cleared the `System` and `Security` logs to remove evidence of their actions.




