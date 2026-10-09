"""Unit tests for linux_auth_parser — run with: python3 -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import linux_auth_parser as p


class TestLinuxAuthParser(unittest.TestCase):
    def test_failed_password_invalid_user_is_high(self):
        ev = p.parse_linux_auth(
            "Oct  2 01:36:38 soc-server sshd[9045]: Failed password for invalid user admin from 45.147.229.11 port 59476 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "high")
        self.assertEqual(ev["action"], "failure")
        self.assertEqual(ev["user"], "admin")
        self.assertEqual(ev["source_ip"], "45.147.229.11")
        self.assertEqual(ev["log_source"], "linux-auth")

    def test_invalid_user_notice_is_high(self):
        ev = p.parse_linux_auth(
            "Oct  2 01:36:38 soc-server sshd[9045]: Invalid user admin from 45.147.229.11"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "high")
        self.assertEqual(ev["user"], "admin")

    def test_failed_password_valid_user_is_medium(self):
        ev = p.parse_linux_auth(
            "Nov 17 15:08:39 localhost sshd[621893]: Failed password for nemo from 192.168.0.7 port 8132 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "medium")
        self.assertEqual(ev["action"], "failure")
        self.assertEqual(ev["user"], "nemo")

    def test_failed_password_supports_dotted_usernames(self):
        ev = p.parse_linux_auth(
            "Nov 17 15:08:39 localhost sshd[621893]: Failed password for john.doe from 192.168.0.7 port 8132 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["user"], "john.doe")

    def test_accepted_password_is_low_success(self):
        ev = p.parse_linux_auth(
            "Oct  2 02:00:00 soc-server sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 2222 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "low")
        self.assertEqual(ev["action"], "success")

    def test_accepted_publickey_is_low_success(self):
        ev = p.parse_linux_auth(
            "Oct  2 02:00:01 soc-server sshd[1235]: Accepted publickey for ubuntu from 10.0.0.5 port 2222 ssh2"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "low")
        self.assertEqual(ev["action"], "success")

    def test_pam_failure_captures_user_despite_double_space(self):
        ev = p.parse_linux_auth(
            "Oct  2 02:10:00 soc-server sshd[2222]: pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.5  user=root"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["severity"], "medium")
        self.assertEqual(ev["source_ip"], "185.220.101.5")
        self.assertEqual(ev["user"], "root")

    def test_sudo_escalation_keeps_command(self):
        ev = p.parse_linux_auth(
            "Oct  2 02:20:00 soc-server sudo:     bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev["event_type"], "privilege_escalation")
        self.assertEqual(ev["severity"], "medium")
        self.assertEqual(ev["user"], "bob")
        self.assertEqual(ev["process_name"], "/bin/bash")

    def test_unknown_lines_are_ignored(self):
        self.assertIsNone(p.parse_linux_auth("Oct  2 02:00:02 soc-server systemd[1]: Started Session 3 of user bob."))
        self.assertIsNone(p.parse_linux_auth("random garbage without any structure"))

    def test_timestamp_taken_from_first_15_chars(self):
        line = "Nov 17 15:08:39 localhost sshd[1]: Failed password for nemo from 192.168.0.7 port 22 ssh2"
        ev = p.parse_linux_auth(line)
        self.assertEqual(ev["timestamp"], line[:15])

    def test_hostname_extracted_as_the_actual_machine(self):
        ev = p.parse_linux_auth(
            "Oct  2 03:00:00 web-prod-01 sshd[9999]: Failed password for root from 10.0.0.1 port 22 ssh2"
        )
        self.assertEqual(ev["host"], "web-prod-01")
        ev2 = p.parse_linux_auth(
            "Oct  2 03:00:00 jump-gateway sudo:     deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"
        )
        self.assertEqual(ev2["host"], "jump-gateway")

    def test_event_id_is_unique_per_parse(self):
        line = "Nov 17 15:08:39 localhost sshd[1]: Failed password for nemo from 192.168.0.7 port 22 ssh2"
        self.assertNotEqual(p.parse_linux_auth(line)["event_id"], p.parse_linux_auth(line)["event_id"])


if __name__ == "__main__":
    unittest.main()
