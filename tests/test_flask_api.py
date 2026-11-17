"""Endpoint integration tests. Requires Flask installed from requirements.txt."""
import io
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
try:
    from app import app
except ModuleNotFoundError:
    app = None


@unittest.skipIf(app is None, "Flask is not installed in the current environment")
class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_homepage_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"THINK", response.data)

    def test_paste_scan(self):
        response = self.client.post("/api/analyze", data={"mode": "paste", "email_text": "From: test@example.com\n\nHello"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["score"], 0)
        self.assertEqual(response.headers.get("Cache-Control"), "no-store, max-age=0")

    def test_upload_scan(self):
        response = self.client.post("/api/analyze", data={
            "mode": "upload", "file": (io.BytesIO((ROOT / "samples/suspicious_invoice.eml").read_bytes()), "invoice.eml")
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["level"], "high")

    def test_reject_wrong_type_and_size(self):
        response = self.client.post("/api/analyze", data={"mode": "upload", "file": (io.BytesIO(b"hello"), "sample.exe")})
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/analyze", data={"mode": "paste", "email_text": "x" * 200001})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
