

# 🛡️ SOC Lab — Day 1 — Windows Host Listening Port Investigation

## 🎯 Objective

To investigate listening network ports on a Windows host system and map them to their owning processes. Validate process legitimacy using native Windows tools and SOC-style investigation methodology.

This lab simulates how a SOC L1 analyst performs host-level triage when reviewing suspicious listening ports.

---

## 🧰 Tools Used

* netstat
* tasklist
* wmic
* PowerShell
* findstr

No third-party security tools were used — only native Windows telemetry commands.

---

## 🔍 Step 1 — Enumerate Listening Ports

Command:

```
netstat -ano
```

### Purpose:

Displays:

* Active network connections
* Listening ports
* Protocol type
* Owning PID

### SOC Relevance:

Used to detect:

* Unknown listeners
* Backdoor ports
* Suspicious outbound connections

---

## 🔎 Step 2 — Map PID to Process Name

Command:

```
tasklist /FI "PID eq 6420"
```

### Purpose:

Maps the discovered PID to its process name.

### Finding:

PID 6420 → mysqld.exe

---

## 📊 Step 3 — Verbose Process Details

Command:

```
tasklist /v /FI "PID eq 6420"
```

### Purpose:

Shows extended process metadata:

* Username
* Session type
* CPU time
* Execution context

### Finding:

Process running under Network Service account.

SOC Note: Service account execution is expected for database services.

---

## 🧭 Step 4 — Extract Executable Path & Command Line

Command:

```
wmic process where processid=6420 get name,executablepath,commandline
```

### Purpose:

Retrieve:

* Full binary path
* Launch arguments
* Configuration files used

### Finding:

Executable Path:

```
C:\Program Files\MySQL\MySQL Server 9.1\bin\mysqld.exe
```

Command Line shows MySQL config file usage.

SOC Interpretation:
Installed location + config usage = legitimate behavior.

---

## 🌐 Step 5 — Network Pivot by PID

Command:

```
netstat -ano | findstr 6420
```

### Purpose:

Filter network connections for that specific process.

### Finding:

```
TCP LISTENING on port 3306
```

SOC Meaning:
Port 3306 = Default MySQL database port → expected.

Localhost established connections also observed → normal DB client behavior.

---

## 🧩 Step 6 — Investigate svchost Service Process

Command:

```
wmic process where processid=14204 get name,executablepath,commandline
```

### Finding:

```
svchost.exe -k LocalService -s CDPSvc
```

SOC Interpretation:

* CDPSvc = Connected Devices Platform Service
* Core Windows component
* Running from System32

Verdict: Legitimate system service.

---

## 🔐 Step 7 — Digital Signature Verification

Command:

```
powershell -Command "Get-AuthenticodeSignature 'C:\Program Files\MySQL\MySQL Server 9.1\bin\mysqld.exe'"
```

### Result:

```
Status: Valid
```

### SOC Meaning:

* Binary is digitally signed
* Vendor trusted
* No tampering detected

---

## 📌 Investigation Summary

| Process     | Port   | Path          | Verdict    |
| ----------- | ------ | ------------- | ---------- |
| mysqld.exe  | 3306   | Program Files | Legitimate |
| svchost.exe | system | System32      | Legitimate |

No suspicious listeners detected during this investigation.

---

## 🧠 Skills Practiced

* Host port enumeration
* PID to process correlation
* Process context analysis
* Executable path validation
* Command-line inspection
* Service attribution
* Digital signature verification
* SOC-style triage workflow

---

## ✅ Conclusion

This lab demonstrates how native Windows tools can be used to perform effective SOC-style host investigations. Mapping listening ports to verified processes is a foundational blue team skill and critical for early threat detection.










 
✅ Build your full SOC lab portfolio structure.
```
