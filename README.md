# Threat Hunting - Suspected Data Exfiltration

For the sake of this lab, we assume the name of the device that John Doe primarily uses is **"zack-bruteforce."**

## 1. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and send it to a private drive, etc.

## 2. Data Collection

**Goal:** We will look at the following tables for indications of malicious actions:
- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

___

This KQL query will check the log files for any recent file creation that includes the `.zip` extension.

```kql
let suspectDevice = "zack-bruteforce";
DeviceFileEvents
| where DeviceName == suspectDevice and FileName contains ".zip"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFolderPath, InitiatingProcessFileName
```
<img width="1444" alt="Screenshot 1 Filename and ProcessFilename" src="https://github.com/user-attachments/assets/5169faa9-6403-4210-949a-86e95e2cc397" />


