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

**Notes:** The command shows the compressed archive was exfiltrated using a command-line tool. The mega: destination indicates the data was uploaded to the cloud storage service MEGA, which is defined as the remote target in the tool’s configuration.

---
## Flag 4 – NA

**Objective**: NA

**Finding**:  
- **NA**: `NA`  

**KQL Query**:
```kql
NA
```


**Notes:** NA

