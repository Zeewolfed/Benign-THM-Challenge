# Benign-THM-Challenge
Write-Up: Suspicious Process Execution Investigation

# Challenge room to investigate a compromised host.

## Objective
Learn more about Splunk and how to investigate the logs.
 Investigate a potential security incident flagged by an IDS, which identified suspicious process execution on an HR department host. 
 Initial findings suggested unauthorized network information gathering and scheduled task execution.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Log Parsing and Analysis: I become familiar with using Splunk to search and filter logs based on specific fields like UserName, ProcessName, and CommandLine, helping to identify unusual or suspicious activity
- Searching for Rare Events: I practice using Splunk queries like rare values to identify outliers or anomalies, such as impersonation or abnormal process executions. This includes finding instances where common processes are being used in an unusual manner, like the use of LOLBINs (Living Off the Land Binaries)
- Investigating Process Execution: I get hands-on experience with process execution analysis, including tracking down which processes were executed by specific users, which is critical for understanding how an attack unfolded
- Identifying Malicious Behavior: By analyzing suspicious activity such as downloads from third-party sites or the execution of potentially malicious payloads.
- Timeline Creation: Splunk help me create a timeline of events related to the attack, such as when a suspicious binary was downloaded, which is useful for both incident response and forensic investigations

### Tools Used
[Bullet Points - Remove this afterwards]

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
