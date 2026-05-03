#!/usr/bin/env python3
"""
Log Analyser
Cross-platform tool for detecting suspicious activity in Windows Event Logs and Linux Syslogs.
Detects: failed logins / brute force, privilege escalation, suspicious processes.
Outputs: CLI + timestamped log file + HTML report.
"""

import os
import re
import sys
import json
import logging
import argparse
import platform
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Optional: Windows Event Log parsing
try:
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5       # failed attempts
BRUTE_FORCE_WINDOW    = 60      # seconds
DEFAULT_LOG_FILE      = "analyser.log"
DEFAULT_REPORT_FILE   = "report.html"

# Windows Event IDs of interest
WINDOWS_EVENT_IDS = {
    4625: "Failed Login",
    4648: "Explicit Credential Login",
    4672: "Privilege Assigned",
    4673: "Privileged Service Called",
    4688: "New Process Created",
    4697: "Service Installed",
    4719: "Audit Policy Changed",
    4720: "User Account Created",
    4728: "User Added to Privileged Group",
    4732: "User Added to Local Admin Group",
    4756: "User Added to Universal Group",
    7045: "New Service Installed",
}

# Linux suspicious process names
SUSPICIOUS_PROCESSES = [
    "nmap", "netcat", "nc", "socat", "metasploit", "msfconsole",
    "mimikatz", "hydra", "medusa", "john", "hashcat", "sqlmap",
    "wireshark", "tcpdump", "aircrack", "nikto", "dirb", "gobuster",
    "wget", "curl", "python -c", "bash -i", "sh -i", "perl -e",
    "ruby -e", "php -r", "powershell", "base64"
]

# Linux privilege escalation patterns
LINUX_PRIV_ESC_PATTERNS = [
    r"sudo\s+.*",
    r"su\s+-?\s*\w*",
    r"chmod\s+[0-7]*[2367][0-7]{2}\s+",   # setuid/setgid bits
    r"chown\s+root",
    r"visudo",
    r"usermod\s+.*-G\s+sudo",
    r"passwd\s+root",
]

# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────

def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("LogAnalyser")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

# ─────────────────────────────────────────────
#  Finding Data Class
# ─────────────────────────────────────────────

class Finding:
    def __init__(self, category: str, severity: str, timestamp: str, source: str, description: str, raw: str = ""):
        self.category    = category
        self.severity    = severity   # HIGH / MEDIUM / LOW
        self.timestamp   = timestamp
        self.source      = source
        self.description = description
        self.raw         = raw

    def to_dict(self):
        return {
            "category":    self.category,
            "severity":    self.severity,
            "timestamp":   self.timestamp,
            "source":      self.source,
            "description": self.description,
        }

# ─────────────────────────────────────────────
#  Windows Event Log Parser
# ─────────────────────────────────────────────

def parse_evtx(filepath: str, logger: logging.Logger) -> list:
    if not EVTX_AVAILABLE:
        logger.error("python-evtx is not installed. Run: pip install python-evtx")
        return []

    findings = []
    failed_logins = defaultdict(list)   # ip/user -> [timestamps]

    logger.info(f"Parsing Windows Event Log: {filepath}")

    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root    = ET.fromstring(xml_str)
                    ns      = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                    event_id_el = root.find(".//e:EventID", ns)
                    time_el     = root.find(".//e:TimeCreated", ns)

                    if event_id_el is None:
                        continue

                    event_id  = int(event_id_el.text)
                    timestamp = time_el.attrib.get("SystemTime", "Unknown") if time_el is not None else "Unknown"

                    if event_id not in WINDOWS_EVENT_IDS:
                        continue

                    # Extract useful data fields
                    data = {}
                    for el in root.findall(".//e:Data", ns):
                        name = el.attrib.get("Name", "")
                        if name:
                            data[name] = el.text or ""

                    label = WINDOWS_EVENT_IDS[event_id]

                    # Failed login / brute force
                    if event_id == 4625:
                        user   = data.get("TargetUserName", "Unknown")
                        ip     = data.get("IpAddress", "Unknown")
                        key    = f"{user}@{ip}"
                        ts_obj = _parse_windows_ts(timestamp)
                        failed_logins[key].append(ts_obj)

                        findings.append(Finding(
                            category    = "Failed Login",
                            severity    = "MEDIUM",
                            timestamp   = timestamp,
                            source      = filepath,
                            description = f"Failed login for user '{user}' from {ip}",
                            raw         = xml_str
                        ))

                    # Privilege escalation
                    elif event_id in (4672, 4673, 4728, 4732, 4756):
                        user = data.get("SubjectUserName", data.get("MemberName", "Unknown"))
                        findings.append(Finding(
                            category    = "Privilege Escalation",
                            severity    = "HIGH",
                            timestamp   = timestamp,
                            source      = filepath,
                            description = f"{label}: user '{user}'",
                            raw         = xml_str
                        ))

                    # Suspicious process
                    elif event_id == 4688:
                        process = data.get("NewProcessName", "Unknown")
                        cmdline = data.get("CommandLine", "")
                        proc_lower = (process + " " + cmdline).lower()
                        if any(sp in proc_lower for sp in SUSPICIOUS_PROCESSES):
                            findings.append(Finding(
                                category    = "Suspicious Process",
                                severity    = "HIGH",
                                timestamp   = timestamp,
                                source      = filepath,
                                description = f"Suspicious process launched: {process} {cmdline}".strip(),
                                raw         = xml_str
                            ))
                        else:
                            findings.append(Finding(
                                category    = "Process Creation",
                                severity    = "LOW",
                                timestamp   = timestamp,
                                source      = filepath,
                                description = f"New process: {process}",
                                raw         = xml_str
                            ))

                    # Misc high-interest events
                    elif event_id in (4697, 4719, 4720, 4745, 7045):
                        findings.append(Finding(
                            category    = "Privilege Escalation",
                            severity    = "HIGH",
                            timestamp   = timestamp,
                            source      = filepath,
                            description = f"{label} detected (Event ID {event_id})",
                            raw         = xml_str
                        ))

                except Exception:
                    continue

    except Exception as e:
        logger.error(f"Failed to parse {filepath}: {e}")
        return findings

    # Brute force detection
    for key, timestamps in failed_logins.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [t for t in timestamps[i:] if t and timestamps[i] and (t - timestamps[i]).total_seconds() <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                user, ip = key.rsplit("@", 1)
                findings.append(Finding(
                    category    = "Brute Force",
                    severity    = "HIGH",
                    timestamp   = str(timestamps[i]),
                    source      = filepath,
                    description = f"Brute force detected: {len(window)} failed logins for '{user}' from {ip} within {BRUTE_FORCE_WINDOW}s",
                ))
                break

    return findings


def _parse_windows_ts(ts_str: str):
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None

# ─────────────────────────────────────────────
#  Linux Syslog Parser
# ─────────────────────────────────────────────

SYSLOG_FAILED_LOGIN_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
    r"(Failed password|authentication failure|Invalid user)\s*(for\s+(?P<user>\S+))?"
    r"(\s+from\s+(?P<ip>[\d\.]+))?",
    re.IGNORECASE
)

SYSLOG_SUDO_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
    r"sudo.*COMMAND=(?P<cmd>.+)",
    re.IGNORECASE
)

SYSLOG_SU_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
    r"su(\[.*?\])?:\s+(?P<msg>.+)",
    re.IGNORECASE
)


def parse_syslog(filepath: str, logger: logging.Logger) -> list:
    findings  = []
    failed_logins = defaultdict(list)

    logger.info(f"Parsing Linux syslog: {filepath}")

    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                timestamp = _extract_syslog_ts(line)

                # Failed login
                m = SYSLOG_FAILED_LOGIN_RE.search(line)
                if m:
                    user = m.group("user") or "Unknown"
                    ip   = m.group("ip")   or "Unknown"
                    key  = f"{user}@{ip}"
                    failed_logins[key].append((timestamp, line))
                    findings.append(Finding(
                        category    = "Failed Login",
                        severity    = "MEDIUM",
                        timestamp   = timestamp,
                        source      = filepath,
                        description = f"Failed login for user '{user}' from {ip}",
                        raw         = line
                    ))
                    continue

                # Sudo usage
                m = SYSLOG_SUDO_RE.search(line)
                if m:
                    cmd = m.group("cmd").strip()
                    findings.append(Finding(
                        category    = "Privilege Escalation",
                        severity    = "MEDIUM",
                        timestamp   = timestamp,
                        source      = filepath,
                        description = f"sudo command executed: {cmd}",
                        raw         = line
                    ))
                    continue

                # su usage
                m = SYSLOG_SU_RE.search(line)
                if m:
                    msg = m.group("msg").strip()
                    severity = "HIGH" if "failed" in msg.lower() else "MEDIUM"
                    findings.append(Finding(
                        category    = "Privilege Escalation",
                        severity    = severity,
                        timestamp   = timestamp,
                        source      = filepath,
                        description = f"su attempt: {msg}",
                        raw         = line
                    ))
                    continue

                # Privilege escalation patterns
                for pattern in LINUX_PRIV_ESC_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(Finding(
                            category    = "Privilege Escalation",
                            severity    = "HIGH",
                            timestamp   = timestamp,
                            source      = filepath,
                            description = f"Potential privilege escalation: {line[:120]}",
                            raw         = line
                        ))
                        break

                # Suspicious processes
                line_lower = line.lower()
                for sp in SUSPICIOUS_PROCESSES:
                    if sp in line_lower:
                        findings.append(Finding(
                            category    = "Suspicious Process",
                            severity    = "HIGH",
                            timestamp   = timestamp,
                            source      = filepath,
                            description = f"Suspicious process/command detected: {line[:120]}",
                            raw         = line
                        ))
                        break

    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
    except PermissionError:
        logger.error(f"Permission denied reading: {filepath}")

    # Brute force detection
    for key, entries in failed_logins.items():
        if len(entries) >= BRUTE_FORCE_THRESHOLD:
            user, ip = key.rsplit("@", 1)
            findings.append(Finding(
                category    = "Brute Force",
                severity    = "HIGH",
                timestamp   = entries[0][0],
                source      = filepath,
                description = f"Brute force detected: {len(entries)} failed logins for '{user}' from {ip}",
            ))

    return findings


def _extract_syslog_ts(line: str) -> str:
    m = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    return m.group(1) if m else "Unknown"

# ─────────────────────────────────────────────
#  HTML Report Generator
# ─────────────────────────────────────────────

SEVERITY_COLOUR = {
    "HIGH":   "#e74c3c",
    "MEDIUM": "#e67e22",
    "LOW":    "#3498db",
}

def generate_html_report(findings: list, report_file: str, logger: logging.Logger):
    high   = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    low    = [f for f in findings if f.severity == "LOW"]

    categories = defaultdict(list)
    for f in findings:
        categories[f.category].append(f)

    rows = ""
    for f in sorted(findings, key=lambda x: ("HIGH","MEDIUM","LOW").index(x.severity) if x.severity in ("HIGH","MEDIUM","LOW") else 3):
        colour = SEVERITY_COLOUR.get(f.severity, "#95a5a6")
        rows += f"""
        <tr>
            <td>{f.timestamp}</td>
            <td><span class="badge" style="background:{colour}">{f.severity}</span></td>
            <td>{f.category}</td>
            <td>{f.description}</td>
            <td class="source">{os.path.basename(f.source)}</td>
        </tr>"""

    category_cards = ""
    for cat, items in categories.items():
        h = sum(1 for i in items if i.severity == "HIGH")
        m = sum(1 for i in items if i.severity == "MEDIUM")
        l = sum(1 for i in items if i.severity == "LOW")
        category_cards += f"""
        <div class="card">
            <div class="card-title">{cat}</div>
            <div class="card-count">{len(items)}</div>
            <div class="card-breakdown">
                <span style="color:{SEVERITY_COLOUR['HIGH']}">High: {h}</span> &nbsp;
                <span style="color:{SEVERITY_COLOUR['MEDIUM']}">Medium: {m}</span> &nbsp;
                <span style="color:{SEVERITY_COLOUR['LOW']}">Low: {l}</span>
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analyser Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 30px; }}
        h1 {{ color: #00d4ff; margin-bottom: 5px; }}
        .meta {{ color: #888; font-size: 0.85em; margin-bottom: 30px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .summary-box {{ background: #16213e; border-radius: 8px; padding: 20px 30px; text-align: center; min-width: 120px; }}
        .summary-box .num {{ font-size: 2.5em; font-weight: bold; }}
        .summary-box .label {{ font-size: 0.8em; color: #aaa; margin-top: 4px; }}
        .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 30px; }}
        .card {{ background: #16213e; border-radius: 8px; padding: 16px 20px; min-width: 180px; }}
        .card-title {{ font-weight: bold; color: #00d4ff; margin-bottom: 8px; }}
        .card-count {{ font-size: 2em; font-weight: bold; }}
        .card-breakdown {{ font-size: 0.78em; margin-top: 6px; }}
        table {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }}
        th {{ background: #0f3460; color: #00d4ff; padding: 12px 14px; text-align: left; font-size: 0.85em; letter-spacing: 0.05em; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid #1a1a2e; font-size: 0.88em; vertical-align: top; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #0f3460; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; color: white; font-size: 0.78em; font-weight: bold; }}
        .source {{ color: #888; font-size: 0.8em; }}
        h2 {{ color: #00d4ff; margin-bottom: 16px; }}
    </style>
</head>
<body>
    <h1>Log Analyser Report</h1>
    <div class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp; Host: {platform.node()}</div>

    <div class="summary">
        <div class="summary-box">
            <div class="num" style="color:#e74c3c">{len(high)}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-box">
            <div class="num" style="color:#e67e22">{len(medium)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-box">
            <div class="num" style="color:#3498db">{len(low)}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-box">
            <div class="num" style="color:#2ecc71">{len(findings)}</div>
            <div class="label">Total</div>
        </div>
    </div>

    <h2>Breakdown by Category</h2>
    <div class="cards">{category_cards}</div>

    <h2>All Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Description</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""

    with open(report_file, "w") as f:
        f.write(html)

    logger.info(f"HTML report saved to '{report_file}'")

# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Analyser — detect suspicious activity in Windows and Linux logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyse a Linux syslog:
    python analyser.py --syslog /var/log/auth.log

  Analyse a Windows Event Log:
    python analyser.py --evtx Security.evtx

  Analyse both with custom output paths:
    python analyser.py --syslog auth.log --evtx Security.evtx --report report.html --log-file run.log
        """
    )

    parser.add_argument("--syslog",      nargs="+", help="Path(s) to Linux syslog file(s)")
    parser.add_argument("--evtx",        nargs="+", help="Path(s) to Windows .evtx file(s)")
    parser.add_argument("--log-file",    default=DEFAULT_LOG_FILE,    help="Path to output log file")
    parser.add_argument("--report",      default=DEFAULT_REPORT_FILE, help="Path to output HTML report")
    parser.add_argument("--threshold",   type=int, default=BRUTE_FORCE_THRESHOLD, help="Failed login threshold for brute force detection")
    parser.add_argument("--window",      type=int, default=BRUTE_FORCE_WINDOW,    help="Time window in seconds for brute force detection")

    args = parser.parse_args()

    if not args.syslog and not args.evtx:
        parser.print_help()
        sys.exit(1)

    logger = setup_logging(args.log_file)
    logger.info(f"Log Analyser started — OS: {platform.system()} {platform.release()}")

    all_findings = []

    if args.syslog:
        for path in args.syslog:
            all_findings.extend(parse_syslog(path, logger))

    if args.evtx:
        for path in args.evtx:
            all_findings.extend(parse_evtx(path, logger))

    # Summary
    high   = [f for f in all_findings if f.severity == "HIGH"]
    medium = [f for f in all_findings if f.severity == "MEDIUM"]
    low    = [f for f in all_findings if f.severity == "LOW"]

    logger.info(f"Analysis complete. Total findings: {len(all_findings)} "
                f"(High: {len(high)}, Medium: {len(medium)}, Low: {len(low)})")

    for f in sorted(all_findings, key=lambda x: x.severity):
        level = logging.WARNING if f.severity in ("HIGH", "MEDIUM") else logging.INFO
        logger.log(level, f"[{f.severity}] [{f.category}] {f.description} | {f.timestamp}")

    generate_html_report(all_findings, args.report, logger)
    logger.info(f"Log file saved to '{args.log_file}'")


if __name__ == "__main__":
    main()
