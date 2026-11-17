"""Run with: python -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analyzers import analyze_email


class TestEmailShield(unittest.TestCase):
    def test_suspicious_multipart_message(self):
        payload = (ROOT / "samples/suspicious_invoice.eml").read_bytes()
        report = analyze_email(payload, source="suspicious_invoice.eml")
        ids = {finding["id"] for finding in report["findings"]}
        self.assertEqual(report["level"], "high")
        self.assertEqual(report["score"], 100)
        self.assertIn("SENDER_REPLY_DOMAIN", ids)
        self.assertIn("URL_IP_ADDRESS", ids)
        self.assertIn("URL_LABEL_MISMATCH", ids)
        self.assertIn("DANGEROUS_FILE_EXTENSION", ids)
        self.assertIn("DOUBLE_EXTENSION", ids)
        self.assertIn("PAYMENT_CHANGE", ids)
        self.assertEqual(len(report["links"]), 1)
        self.assertEqual(report["attachments"][0]["filename"], "statement.pdf.exe")
        self.assertEqual(report["authentication_claims"][0]["method"], "SPF")
        self.assertFalse(report["authentication_claims"][0]["verified"])

    def test_normal_message_not_reported_as_safe(self):
        report = analyze_email((ROOT / "samples/simple_newsletter.eml").read_bytes())
        self.assertEqual(report["level"], "low")
        self.assertEqual(report["score"], 0)
        self.assertTrue(report["limitations"])
        self.assertIn("not establish", report["recommendations"][-1])

    def test_header_only(self):
        report = analyze_email(b"From: Me <me@example.com>\nReply-To: nope@another.test\nSubject: Hello\n")
        self.assertTrue(report["header_only"])
        self.assertIn("SENDER_REPLY_DOMAIN", {x["id"] for x in report["findings"]})

    def test_plain_body(self):
        report = analyze_email(b"URGENT: wire transfer to our new bank account")
        self.assertIn("PAYMENT_CHANGE", {x["id"] for x in report["findings"]})

    def test_html_script_is_not_executed_or_followed(self):
        raw = b'From: a@b.test\nContent-Type: text/html\n\n<a href="javascript:alert(1)">Click</a>'
        report = analyze_email(raw)
        self.assertIn("NON_WEB_LINK", {x["id"] for x in report["findings"]})
        self.assertEqual(report["links"], [])

    def test_url_shortener(self):
        report = analyze_email(b"From: a@b.test\n\nSee https://bit.ly/example")
        self.assertIn("URL_SHORTENER", {x["id"] for x in report["findings"]})

    def test_reject_oversize_and_blank(self):
        with self.assertRaises(ValueError):
            analyze_email(b" ")
        with self.assertRaises(ValueError):
            analyze_email(b"x" * (2 * 1024 * 1024 + 1))

    def test_authentication_pass_not_verified(self):
        report = analyze_email(b"From: me@example.com\nAuthentication-Results: foo; spf=pass; dkim=pass\n\nHi")
        self.assertEqual(len(report["authentication_claims"]), 2)
        self.assertFalse(any(x["verified"] for x in report["authentication_claims"]))
        self.assertEqual(report["score"], 0)

    def test_email_address_in_display_name(self):
        report = analyze_email(b'From: "support@trusted.example" <attacker@other.example>\n\nHi')
        self.assertIn("DISPLAY_NAME_EMAIL", {x["id"] for x in report["findings"]})


if __name__ == "__main__":
    unittest.main()
