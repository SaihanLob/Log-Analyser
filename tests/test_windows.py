"""Tests for the Windows event analysis, using hand-written event XML so no
.evtx file is needed."""

import logging
from datetime import datetime
from html import escape

import analyser

LOGGER = logging.getLogger("test")
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(event_id, time, **data):
    """Build the XML for one Windows event, in the same shape python-evtx produces."""
    fields = "".join(f'<Data Name="{k}">{escape(str(v))}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{time}"/></System>'
            f'<EventData>{fields}</EventData></Event>')


def analyse(events, **kwargs):
    return analyser.analyse_windows_events(events, "Security.evtx", LOGGER, **kwargs)


def by_category(findings, category):
    return [f for f in findings if f.category == category]


def rdp_spray(ip="203.0.113.45"):
    """Six failed RDP logins against different users within 25 seconds,
    using Windows' native 7-digit fractional timestamps."""
    users = ["administrator", "admin", "backup", "svc_sql", "jsmith", "administrator"]
    return [event(4625, f"2026-11-01T07:15:{i * 5:02d}.1234567Z",
                  TargetUserName=u, IpAddress=ip, LogonType="10")
            for i, u in enumerate(users)]


def test_windows_timestamps_with_seven_fractional_digits():
    dt = analyser._parse_windows_ts("2026-11-01T07:15:00.1234567Z")
    assert dt == datetime(2026, 11, 1, 7, 15, 0, 123456)
    assert analyser._parse_windows_ts("not a time") is None


def test_brute_force_grouped_by_ip_across_usernames():
    brute = by_category(analyse(rdp_spray()), "Brute Force")
    assert len(brute) == 1
    assert "6 failed logins from 203.0.113.45" in brute[0].description
    assert "svc_sql" in brute[0].description


def test_remote_login_after_brute_force_is_possible_compromise():
    events = rdp_spray() + [event(4624, "2026-11-01T07:15:40.0000000Z",
                                  TargetUserName="jsmith", IpAddress="203.0.113.45", LogonType="10")]
    compromise = by_category(analyse(events), "Possible Compromise")
    assert len(compromise) == 1
    assert "'jsmith'" in compromise[0].description


def test_threshold_and_window_options():
    assert by_category(analyse(rdp_spray(), threshold=10), "Brute Force") == []
    assert by_category(analyse(rdp_spray(), window=10), "Brute Force") == []


def test_bad_timestamp_does_not_crash():
    events = rdp_spray() + [event(4625, "garbage", TargetUserName="x", IpAddress="203.0.113.45")]
    assert len(by_category(analyse(events), "Brute Force")) == 1


def test_privileged_logon_ignores_system_accounts():
    events = [
        event(4672, "2026-11-01T08:00:00Z", SubjectUserName="SYSTEM"),
        event(4672, "2026-11-01T08:00:01Z", SubjectUserName="WEB01$"),
        event(4672, "2026-11-01T08:00:02Z", SubjectUserName="bob"),
    ]
    findings = analyse(events)
    assert len(findings) == 1
    assert findings[0].severity == "LOW" and "bob" in findings[0].description


def test_only_suspicious_processes_are_reported():
    events = [
        event(4688, "2026-11-01T08:00:00Z", NewProcessName=r"C:\Windows\System32\notepad.exe",
              CommandLine="notepad.exe report.txt"),
        event(4688, "2026-11-01T08:00:01Z", NewProcessName=r"C:\Users\Public\mimikatz.exe",
              CommandLine=r"C:\Users\Public\mimikatz.exe sekurlsa::logonpasswords"),
    ]
    findings = analyse(events)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH" and "mimikatz" in findings[0].description


def test_group_change_names_member_group_and_actor():
    findings = analyse([event(4732, "2026-11-01T08:00:00Z", MemberName="-",
                              MemberSid="S-1-5-21-1-2-3-1005", TargetUserName="Administrators",
                              SubjectUserName="jsmith")])
    assert findings[0].severity == "HIGH"
    assert findings[0].description == \
        "S-1-5-21-1-2-3-1005 added to privileged group 'Administrators' by 'jsmith'"


def test_ordinary_group_change_is_low():
    findings = analyse([event(4732, "2026-11-01T08:00:00Z", MemberSid="S-1-5-21-1-2-3-1005",
                              TargetUserName="Users", SubjectUserName="jsmith")])
    assert findings[0].severity == "LOW" and findings[0].category == "Group Membership"


def test_account_created_and_service_installed_are_high():
    events = [
        event(4720, "2026-11-01T08:00:00Z", TargetUserName="sysupdate", SubjectUserName="jsmith"),
        event(7045, "2026-11-01T08:00:01Z", ServiceName="Updater",
              ImagePath="powershell.exe -nop -w hidden -enc SQBFAFgA"),
    ]
    findings = analyse(events)
    assert {f.category for f in findings} == {"Account Created", "Service Installed"}
    assert all(f.severity == "HIGH" for f in findings)
    service = by_category(findings, "Service Installed")[0]
    assert "Dual-use tool 'powershell'" in service.description
