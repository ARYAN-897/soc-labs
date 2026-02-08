

#  SOC Lab — Day 3 — Suspicious Process Tree Investigation (LOLBin Pattern)

##  Objective

To investigate parent–child process relationships on a Windows system and detect suspicious execution chains using native command-line tools. The lab focuses on process lineage analysis — a core SOC analyst skill for detecting LOLBin and script-based attack patterns.

---

#  Lab Scenario

A suspicious-looking execution chain was simulated using built-in Windows binaries to mimic LOLBin-style behavior.

Simulated chain:

```
cmd.exe → powershell.exe → notepad.exe
```

This pattern is often seen in script launchers, LOLBin abuse, and malware staging activity.

---

#  Tools Used

* tasklist
* wmic process
* findstr
* CMD (Command Prompt)

All investigation performed using native Windows tools only.

---

#  Simulation Command Used

```
cmd /c powershell -nop -w hidden -c "Start-Process notepad"
```

### Why This Is Suspicious (SOC Context)

Flags used:

* `-nop` → No PowerShell profile
* `-w hidden` → Hidden execution
* Scripted child process launch

These flags are commonly observed in malicious PowerShell activity.

---

#  Investigation Steps

---

## Step 1 — Identify Notepad Processes

Command:

```
tasklist | findstr notepad
```

Result:

Multiple notepad.exe instances detected.

---

## Step 2 — Extract Parent Process Mapping

Command:

```
wmic process where name="notepad.exe" get processid,parentprocessid,commandline
```

Result:

```
ParentPID   PID
19148       9824
23948       15756
```

Finding:

Two notepad processes running with different parent processes.

---

## Step 3 — Verify Child Processes

Commands:

```
tasklist /FI "PID eq 15756"
tasklist /FI "PID eq 9824"
```

Result:

Both notepad processes confirmed running.

---

## Step 4 — Investigate Parent Processes

Commands:

```
tasklist /FI "PID eq 23948"
tasklist /FI "PID eq 19148"
```

Result:

```
No tasks are running which match the specified criteria
```

---

#  SOC Interpretation

The parent processes had already terminated at the time of investigation.

This indicates **short-lived launcher behavior**, where:

```
Launcher process starts payload → exits quickly
Child process continues running
```

This pattern is commonly observed in:

* Script launchers
* PowerShell LOLBin abuse
* Malware staging chains
* cmd /c execution chains

---

#  Detection Insight

Normal behavior:

```
explorer.exe → notepad.exe
```

Suspicious behavior pattern:

```
powershell.exe → notepad.exe
cmd.exe → powershell.exe → child process
```

GUI applications launched from hidden PowerShell or script chains are high-signal SOC indicators.

---

#  SOC Detection Value

This lab demonstrates why **process tree analysis is critical**:

A single process may appear legitimate, but the **execution chain reveals suspicious behavior**.

SOC tools (EDR/SIEM) detect these using:

* Parent-child rules
* Command-line flags
* LOLBin behavior patterns
* Short-lived launcher detection

---

#  Risk Classification (Lab Scenario)

**Risk Level:** Medium (behaviorally suspicious pattern)
**Type:** LOLBin-style execution chain
**Impact:** Demonstrates attack-style process lineage behavior

---

#  Skills Practiced

* Process enumeration
* Parent-child PID mapping
* Multi-instance process handling
* Short-lived parent detection
* LOLBin behavior recognition
* SOC investigation workflow
* Command-line process forensics

---

#  Analyst Conclusion

Process lineage analysis revealed multiple notepad instances launched via short-lived parent processes. The observed execution pattern matches LOLBin-style and script-based launcher behavior frequently seen in real SOC investigations.

---


