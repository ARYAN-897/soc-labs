SOC Lab 4 — Failed Login Brute Force Detection
Objective

Detect repeated failed login attempts using Windows Security logs.

Method

Multiple incorrect login attempts were generated from the Windows lock screen. Security logs were analyzed using Event Viewer filtered on Event ID 4625.

Event ID Investigated

4625 — Failed Logon Attempt

Evidence Observed

4 failed login events

Very short time interval (~3 seconds apart)

Logon Type = 2 (Interactive)

Status Code = 0xC000006D (Bad credentials)

Source Address = 127.0.0.1

Caller Process = svchost.exe

Detection Pattern

Rapid repeated failed login attempts detected within seconds — matches brute-force attempt behavior pattern.

SOC Relevance

Event ID 4625 is heavily used in SIEM detection rules for:

Brute force attempts

Credential stuffing

Password guessing attacks

Skills Practiced

Windows Security log filtering

Event ID analysis

Authentication failure investigation

Brute force pattern recognition

SOC alert triage workflow
