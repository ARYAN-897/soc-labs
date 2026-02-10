🛡️ SOC Lab 5 — Scheduled Task Persistence Detection
🎯 Objective

To simulate attacker persistence using Windows Scheduled Tasks and detect task creation activity using Task Scheduler Operational logs — replicating a common SOC persistence detection scenario.

🧪 Lab Scenario

Attackers often create scheduled tasks to maintain persistence after gaining access to a system. These tasks automatically execute malicious payloads at fixed intervals or system startup.

In this lab, a scheduled task was created to simulate persistence behavior and then investigated using native Windows logging telemetry.

⚙️ Persistence Simulation — Task Creation

A scheduled task was created using the Windows schtasks utility.

Command Used
schtasks /create /sc minute /mo 5 /tn "UpdaterCheck2" /tr notepad.exe

Meaning

Create a scheduled task

Run every 5 minutes

Task name: UpdaterCheck2

Program executed: notepad.exe

Simulates attacker persistence behavior

🔍 Task Enumeration — Detection Step

All scheduled tasks were listed using:

schtasks /query /fo LIST /v


Targeted investigation:

schtasks /query /tn "UpdaterCheck2" /v /fo LIST

Fields Reviewed

Task name

Schedule frequency

Command executed

Run user context

Next run time

Task path

📊 Telemetry Source — Task Scheduler Logs

Log location:

Event Viewer →
Applications and Services Logs →
Microsoft →
Windows →
TaskScheduler →
Operational


Operational log channel was initially disabled and had to be manually enabled.

🚨 Key Detection Event Observed
Event ID 106 — Task Registered

Evidence captured:

Event ID: 106
Source: TaskScheduler
Log: Microsoft-Windows-TaskScheduler/Operational
Message:
User "LAPTOP-XXXX\mathu" registered Task Scheduler task "\UpdaterCheck2"

SOC Interpretation

Event ID 106 confirms:

New scheduled task created

Persistence mechanism established

User account responsible recorded

High-value persistence indicator

🧾 Additional Task Lifecycle Events Observed
Event ID	Meaning	SOC Value
100	Task started	Execution evidence
102	Task completed	Execution end
129	Task process created	Process launch trace
200	Action started	Payload execution
201	Action completed	Execution finished
141	Task updated	Modification indicator
🧠 SOC Detection Logic

Typical SIEM detection rule:

IF EventID = 106
AND TaskName NOT in approved baseline
THEN alert = Possible Persistence via Scheduled Task


SOC teams baseline legitimate tasks and alert on new or suspicious task names.

⚠️ Noise vs Signal Example Observed

Event ID 114 was observed for a Google updater task failure.

SOC conclusion:

Legitimate updater task

Misfire condition

Not malicious

Demonstrates need for false positive filtering

🧹 Remediation Step — Task Removal

Simulated persistence task was removed.

schtasks /delete /tn "UpdaterCheck2" /f


Verification:

schtasks /query | findstr UpdaterCheck2


No output confirmed successful removal.

✅ Skills Practiced

Scheduled task persistence simulation

Task enumeration via command line

Task action inspection

Windows Task Scheduler telemetry analysis

Event ID 106 persistence detection

Log channel enablement

False positive differentiation

Persistence artifact remediation

🎯 SOC Relevance

Scheduled task abuse is a widely used persistence technique in:

Malware infections

Red team operations

Post-exploitation frameworks

Living-off-the-land attacks

Detection of Event ID 106 is a core SOC monitoring practice.
