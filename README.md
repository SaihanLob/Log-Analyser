# Log Analyser

A cross-platform log analysis tool written in Python. It parses Windows Event Logs and Linux syslogs, identifies suspicious activity across three detection categories, and produces both a timestamped log file and an HTML report summarising every finding by severity.

This was built as a blue team and SOC learning project, with the goal of understanding how log-based threat detection works at a practical level before working with full SIEM platforms like Splunk or Wazuh.

---

## Features

- Parses Windows Event Logs (.evtx) and Linux syslogs (auth.log, syslog)
- Detects failed logins and brute force patterns, privilege escalation, and suspicious processes
- Brute force detection using a configurable threshold and time window
- Severity classification across High, Medium, and Low findings
- Timestamped log file output for audit trail purposes
- Self-contained HTML report with a summary dashboard and full findings table
- Accepts multiple log files in a single run
- Cross-platform support: Windows and Linux

---

## Detection Coverage

**Failed Logins and Brute Force**

Flags every failed authentication attempt and groups them by user and source IP. If the number of failures from a single source exceeds the configured threshold within the time window, a brute force finding is raised at High severity.

**Privilege Escalation**

On Linux, detects sudo commands, su attempts, chmod operations that set setuid or setgid bits, chown to root, and modifications to sudoers. On Windows, watches for Event IDs covering privilege assignment, users being added to administrative groups, new services being installed, and audit policy changes.

**Suspicious Processes**

Flags known offensive tools and techniques including nmap, netcat, socat, Hydra, Mimikatz, sqlmap, reverse shell patterns, and base64-encoded command execution. On Windows this is pulled from process creation events (Event ID 4688). On Linux it is matched against log lines directly.

---

## Windows Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 4625 | Failed login |
| 4648 | Explicit credential login |
| 4672 | Special privileges assigned |
| 4673 | Privileged service called |
| 4688 | New process created |
| 4697 | Service installed |
| 4719 | Audit policy changed |
| 4720 | User account created |
| 4728 | User added to privileged group |
| 4732 | User added to local admin group |
| 7045 | New service installed |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/log-analyser.git
cd log-analyser
pip install -r requirements.txt
```

The only external dependency is `python-evtx`, which is required for parsing Windows Event Logs. If you are only analysing Linux syslogs, the tool will work without it.

---

## Usage

### Analyse a Linux syslog

```bash
python analyser.py --syslog /var/log/auth.log
```

### Analyse a Windows Event Log

```bash
python analyser.py --evtx Security.evtx
```

### Analyse both at once

```bash
python analyser.py --syslog /var/log/auth.log --evtx Security.evtx
```

### Analyse multiple files of the same type

```bash
python analyser.py --syslog auth.log syslog messages
```

### Custom output paths and brute force tuning

```bash
python analyser.py --syslog auth.log --report my_report.html --log-file run.log --threshold 3 --window 30
```

---

## Output

### CLI and Log File (`analyser.log`)

Every finding is printed to the terminal and written to the log file with a timestamp and severity label.

```
[2024-01-15 10:00:09] [WARNING] [HIGH]   [Brute Force] Brute force detected: 5 failed logins for 'root' from 192.168.1.100 within 60s
[2024-01-15 10:01:00] [WARNING] [MEDIUM] [Privilege Escalation] sudo command executed: /bin/bash
[2024-01-15 10:02:00] [WARNING] [HIGH]   [Privilege Escalation] su attempt: FAILED su for root by bob
[2024-01-15 10:03:00] [WARNING] [HIGH]   [Suspicious Process] Suspicious process/command detected: nmap -sS 10.0.0.1
```

### HTML Report (`report.html`)

Open the report in any browser. It includes a severity summary, a breakdown of findings by category, and a full sortable table of every event with its timestamp, severity badge, category, description, and source file.

---

## Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--syslog` | Path(s) to Linux syslog file(s) | None |
| `--evtx` | Path(s) to Windows .evtx file(s) | None |
| `--log-file` | Path to output log file | `analyser.log` |
| `--report` | Path to output HTML report | `report.html` |
| `--threshold` | Failed login count to trigger brute force alert | `5` |
| `--window` | Time window in seconds for brute force detection | `60` |

---

## Real-World Use Cases

Log analysis is one of the most fundamental skills in SOC work. Practical applications of this tool include investigating failed SSH login patterns on a Linux server, reviewing Windows Security logs after a suspected intrusion, triaging auth.log files pulled from a compromised machine during an incident response engagement, and building familiarity with the Event IDs that underpin most SIEM detection rules.

---

## Project Structure

```
log-analyser/
├── analyser.py          # Main script
├── requirements.txt     # Python dependencies
├── analyser.log         # Generated at runtime (gitignored)
└── report.html          # Generated at runtime (gitignored)
```

---

## Security Notes

Log files often contain sensitive information including usernames, IP addresses, and internal hostnames. Never commit real log files to a public repository. The `.gitignore` excludes `.log` and `.evtx` files by default for this reason. If you are sharing sample logs for demonstration purposes, sanitise them first.

---

## Skills Demonstrated

`Python` · `Log Parsing` · `Regex` · `Brute Force Detection` · `Windows Event Log Analysis` · `Linux Syslog Analysis` · `HTML Report Generation` · `Blue Team / Defensive Security` · `SOC Tooling`

---

## Licence

MIT
