# Threat Hunting Scenario: Suspected Data Exfiltration from PIP'd Employee

## 1. Preparation

**Scenario**:  
An employee named **John Doe**, under a performance improvement plan (PIP), is suspected of planning to exfiltrate sensitive data. The device being investigated is `ash-threathunt`, onboarded to Microsoft Defender for Endpoint (MDE).  

**Hypothesis**:  
John, who has administrative rights, may attempt to archive sensitive information and move it to a private location or drive.

---

## 2. Data Collection

**Data Sources Used**:
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`

Collected logs from all the above tables using advanced hunting queries in MDE to ensure full coverage around file and process behavior.

---

## 3. Data Analysis

**Initial Query - Archive Application Use**  
Searched for known archiving tools used on the target device:

```kql
let archive_applications = dynamic(["winrar.exe", "7z.exe", "winzip32.exe", "peazip.exe", "Bandizip.exe", "UniExtract.exe", "POWERARC.EXE", "IZArc.exe", "AshampooZIP.exe", "FreeArc.exe"]);
let VMName = "ash-threathunt";
DeviceProcessEvents
| where FileName has_any(archive_applications)
| order by Timestamp desc
```

This revealed the use of `7z.exe` for archiving.

---

## 4. Timeline Investigation

After identifying `.zip` creation activity, I performed time-based pivoting on `DeviceProcessEvents` and `DeviceNetworkEvents`.

### File Creation Search
```kql
DeviceFileEvents
| where DeviceName contains "Ash"
| where FileName endswith ".zip"
| order by Timestamp desc

```


![image](https://github.com/user-attachments/assets/c9439c9b-9bc2-4e94-ad39-0bb84291f5df)



### Process Correlation (±1 minute)
```kql
let VMName = "ash-threathunt";
let specificTime = datetime(2025-04-10T23:03:10.8500709Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| where AccountName == "employee"
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/6e9c047e-0261-4c29-9a4c-4db85f08b9ff)


Finding: PowerShell silently installed 7-Zip, which was then used to archive employee data.

### Network Activity Pivot (±2 minutes)
```kql
let VMName = "ash-threathunt";
let specificTime = datetime(2025-04-10T23:03:10.8500709Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/59f6addf-6b57-47f3-aa05-9cc9bd5b61b6)


Result: No signs of data exfiltration over the network at the time.

---

## 5. MITRE ATT&CK TTP Mapping

### Mapped Techniques

**Tactic: Collection**  
- `T1560.001` – Archive via Utility: Use of 7-Zip to compress sensitive data.

**Tactic: Execution**  
- `T1059.001` – PowerShell: Scripted execution for silent 7-Zip install.

**Tactic: Defense Evasion**  
- `T1218.011` – Signed Binary Proxy Execution: PowerShell likely used trusted system processes to avoid detection.

**Tactic: Impact (Optional)**  
- `T1074` – Data Staged: Files were moved to a “backup” directory as staging behavior.

---

## 6. Response

**Action Taken**:
- Immediately isolated the system after confirming suspicious activity.
- Created a custom alert to detect and isolate machines that create an excessive number of `.zip` files (threshold >50 in a short period).

![image](https://github.com/user-attachments/assets/3cec3a7a-cbba-4839-9cb5-238e59dc133d)


---

## 7. Improvement Plan

### 1. Prevent Silent Tool Installation
- **Issue**: PowerShell was used to silently install 7-Zip.
- **Improvement**:
  - Deploy AppLocker or WDAC to block unauthorized tools.
  - Use EDR rules to alert on silent installations via scripting tools.

### 2. Behavior-Based Archiver Monitoring
- **Issue**: Archiving tools like 7-Zip are often misused.
- **Improvement**:
  - Alert on execution of known archivers in sensitive directories.
  - Monitor for high-frequency `.zip` creation or archiving in HR or internal shares.
  - Set thresholds (e.g., 50+ .zip files in 10 minutes) for behavioral detections.

### 3. Faster Correlation
- Automate query chaining to pivot around detected process/file events quickly.
- Create MDE hunting dashboards and bookmarks for repeatable playbooks.

---

## Summary

This hunt revealed the misuse of PowerShell and 7-Zip to archive sensitive files by a potentially disgruntled employee. No exfiltration occurred, but the behavior was identified early, allowing for timely isolation and mitigation.

> **Key Learning**: Silent and trusted utilities are frequently used for insider threats. A behavior-based detection approach is more effective than relying on signatures or static rules alone.
