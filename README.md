# Rapid7 Detection Rule – Persistence via Scheduled Task

## Project Overview

This project demonstrates creation of a Rapid7 custom detection rule to identify potential persistence mechanisms via scheduled task execution.

Attackers frequently leverage scheduled tasks to maintain persistence or automate malicious actions.

---

## Detection Goal

Detect execution of:

```txt
schtasks.exe
```

Potential attacker objectives:

- Persistence
- Scheduled malware execution
- Automation
- Credential theft staging

---

## Technologies Used

- Rapid7 InsightIDR
- Windows Command Prompt
- Windows VM
- Process Monitoring

---

## Demo Video

▶️ Add video here

---

## Detection Rule Configuration

### Rule Name

```txt
Persistence via Scheduled Tasks
```

### Description

Detects execution of scheduled task creation which may indicate persistence or attacker automation.

### Rule Action

```txt
Alert
Priority: High
```

### Event Type

```txt
Endpoint Process Start Event
```

### Detection Query

```txt
where(process.name = "schtasks.exe")
```

---

## SOP / Walkthrough

### Step 1 — Create Detection Rule

Navigate:

```txt
Detection Rules → Create Custom Rule
```

---

### Step 2 — Configure Rule

Configured:

- Alert action
- High priority
- Endpoint Process Start Event

---

### Step 3 — Add Query

Detection logic:

```txt
process.name = "schtasks.exe"
```

Purpose:

Detect potential persistence activity.

---

### Step 4 — Trigger Test Activity

Opened Command Prompt as Administrator.

Executed:

```cmd
schtasks /create /tn "Updater" /tr notepad.exe /sc onlogon
```

Purpose:

Simulate scheduled task persistence.

---

### Step 5 — Validate Logs

Reviewed log search to confirm:

```txt
schtasks.exe
```

was ingested.

---

### Step 6 — Validate Alert

Reviewed:

```txt
Alerts
```

Confirmed:

- Custom detection triggered
- Rule functioning correctly

---

## Outcome

Successfully implemented and validated scheduled task persistence detection within Rapid7 InsightIDR.

---

## MITRE ATT&CK Mapping

Suggested:

```txt
T1053.005 — Scheduled Task/Job
```

---

## Skills Demonstrated

- Detection engineering
- Windows persistence detection
- Rapid7 alerting
- SIEM validation
- Endpoint monitoring
