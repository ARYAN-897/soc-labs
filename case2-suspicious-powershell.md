🛡️ SOC Lab — Case 2 — Suspicious PowerShell Execution Detection
Objective

Detect suspicious PowerShell activity using process and command-line investigation.

Simulated Suspicious Command
powershell -nop -w hidden -c "Start-Sleep 300"

Detection Steps Performed

Process discovery

tasklist | findstr powershell


Command-line extraction

wmic process where processid=22140 get commandline


Parent process tracing

wmic process where processid=22140 get parentprocessid

Suspicious Indicators Observed

PowerShell executed with no profile flag

Hidden window execution

Script command parameter used

Background execution behavior

SOC Risk Classification

Medium — behavior matches common malicious PowerShell staging patterns.

Analyst Conclusion

Command-line flags and execution style match frequently abused PowerShell techniques used in initial malware staging.

🎯 Lab Status
Component	Status
Process detection	✅
Command line captured	✅
Suspicious flags identified	✅
Parent PID captured	✅
SOC reasoning applied	✅

Case 2 Lab = SUCCESSFULLY COMPLETED 🛡️
