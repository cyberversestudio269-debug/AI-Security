import os
import secrets
import socket
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock
from urllib.parse import urlsplit


_TEST_DB_PATH = os.path.join(
    tempfile.gettempdir(), "ai-risk-scanner-test-%s.sqlite3" % secrets.token_hex(6)
)
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB_PATH.replace("\\", "/")

import api
import maintenance
import target_security
from fastapi.testclient import TestClient


class TargetSecurityTests(unittest.TestCase):
    def test_rejects_http_ip_literals_and_embedded_credentials(self):
        for url in (
            "http://example.test/chat",
            "https://127.0.0.1/chat",
            "https://user@example.test/chat",
        ):
            with self.subTest(url=url):
                with self.assertRaises(target_security.UnsafeTargetError):
                    target_security.parse_public_https_url(url)

    def test_rejects_private_dns_results(self):
        private_record = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.5", 443))
        ]
        with mock.patch("target_security.socket.getaddrinfo", return_value=private_record):
            with self.assertRaises(target_security.UnsafeTargetError):
                target_security.parse_public_https_url("https://example.test/chat")

    def test_does_not_follow_target_redirects(self):
        class FakeResponse:
            status = 302

        class FakeConnection:
            closed = False

            def __init__(self, *args, **kwargs):
                pass

            def request(self, *args, **kwargs):
                pass

            def getresponse(self):
                return FakeResponse()

            def close(self):
                self.closed = True

        parsed = urlsplit("https://example.test/chat")
        connection = FakeConnection()
        with mock.patch(
            "target_security.parse_public_https_url",
            return_value=(parsed, "example.test", 443, ["1.1.1.1"]),
        ), mock.patch(
            "target_security._PinnedHTTPSConnection", return_value=connection
        ):
            with self.assertRaises(target_security.UnsafeTargetError):
                target_security.safe_https_request("GET", "https://example.test/chat")
        self.assertTrue(connection.closed)

    def test_dns_and_file_proofs_require_the_exact_challenge(self):
        token = "verification-token"
        digest = target_security.challenge_digest(token)

        class FakeTxt:
            strings = (token.encode("utf-8"),)

        with mock.patch("target_security.dns.resolver.resolve", return_value=[FakeTxt()]):
            self.assertTrue(target_security.verify_dns_challenge("example.test", digest))
            self.assertFalse(
                target_security.verify_dns_challenge(
                    "example.test", target_security.challenge_digest("other-token")
                )
            )

        with mock.patch(
            "target_security.safe_https_request", return_value=token.encode("utf-8")
        ) as request:
            self.assertTrue(
                target_security.verify_file_challenge("example.test", 443, digest)
            )
        self.assertEqual(
            request.call_args.args[1],
            "https://example.test/.well-known/ai-risk-scanner-verification.txt",
        )


class PilotApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(api.app)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client.__exit__(None, None, None)
        api.engine.dispose()
        if os.path.exists(_TEST_DB_PATH):
            os.unlink(_TEST_DB_PATH)

    def create_account(self, email):
        response = self.client.post(
            "/api/auth/register",
            json={"email": email, "password": "a-unique-password-123"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertNotIn("access_token", response.json())
        session_cookie = response.cookies.get(api.SESSION_COOKIE_NAME)
        self.assertTrue(session_cookie)
        set_cookie = response.headers["set-cookie"].lower()
        self.assertIn("httponly", set_cookie)
        self.assertIn("samesite=strict", set_cookie)
        headers = {"Cookie": "%s=%s" % (api.SESSION_COOKIE_NAME, session_cookie)}
        account = self.client.get(
            "/api/me", headers=headers
        )
        self.assertEqual(account.status_code, 200, account.text)
        return headers, account.json()["id"]

    def test_web_ui_and_static_assets_are_served_with_security_headers(self):
        page = self.client.get("/")
        script = self.client.get("/static/app.js")
        self.assertEqual(page.status_code, 200)
        self.assertIn("AI Risk Scanner", page.text)
        self.assertEqual(script.status_code, 200)
        self.assertIn("textContent", script.text)
        self.assertNotIn("sessionStorage", script.text)
        self.assertNotIn("localStorage", script.text)
        self.assertNotIn("Authorization", script.text)
        self.assertEqual(page.headers["x-frame-options"], "DENY")
        self.assertIn("default-src 'self'", page.headers["content-security-policy"])

    def test_scan_results_are_account_scoped_and_demo_exports_pdf(self):
        headers_a, owner_a = self.create_account("owner-a@example.test")
        headers_b, _ = self.create_account("owner-b@example.test")

        with api.SessionLocal() as db:
            scan = api.Scan(
                owner_id=owner_a,
                target_id=None,
                company_name="Test Client",
                questionnaire={
                    "uses_personal_data": True,
                    "has_human_review": False,
                    "has_role_based_access": False,
                    "has_retention_policy": False,
                    "discloses_ai_use": False,
                },
                status="completed",
                result_json={
                    "summary": {
                        "risk_score": 0,
                        "risk_level": "LOW",
                        "tests_run": 0,
                        "failed": 0,
                        "needs_review": 0,
                        "errors": 0,
                        "demo_mode": True,
                    },
                    "results": [],
                    "questionnaire": {"uses_personal_data": True},
                },
            )
            db.add(scan)
            db.commit()
            scan_id = scan.id

        own = self.client.get(
            "/api/scans/%d" % scan_id,
            headers=headers_a,
        )
        other = self.client.get(
            "/api/scans/%d" % scan_id,
            headers=headers_b,
        )
        self.assertEqual(own.status_code, 200)
        self.assertEqual(other.status_code, 404)

        response = self.client.post(
            "/api/scans",
            headers=headers_b,
            json={"demo": True, "company_name": "Offline Demo"},
        )
        self.assertEqual(response.status_code, 202, response.text)
        demo_id = response.json()["id"]
        details = self.client.get(
            "/api/scans/%d" % demo_id,
            headers=headers_b,
        )
        self.assertEqual(details.status_code, 200, details.text)
        self.assertEqual(details.json()["status"], "completed")
        self.assertTrue(details.json()["result"]["summary"]["demo_mode"])

        report = self.client.get(
            "/api/scans/%d/report.pdf" % demo_id,
            headers=headers_b,
        )
        self.assertEqual(report.status_code, 200, report.text[:200])
        self.assertEqual(report.headers["content-type"], "application/pdf")
        self.assertTrue(report.content.startswith(b"%PDF"))

    def test_live_scan_requires_verified_account_owned_target(self):
        headers, owner_id = self.create_account("owner-c@example.test")
        with api.SessionLocal() as db:
            target = api.Target(
                owner_id=owner_id,
                url="https://127.0.0.1/v1/chat/completions",
                host="127.0.0.1",
                port=443,
                model="default",
                challenge_hash="not-a-real-challenge",
            )
            db.add(target)
            db.commit()
            target_id = target.id

        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            response = self.client.post(
                "/api/scans",
                headers=headers,
                json={
                    "target_id": target_id,
                    "authorized": True,
                    "company_name": "Test Client",
                },
            )
        self.assertEqual(response.status_code, 403)

    def test_account_deletion_removes_owned_scans_targets_and_sessions(self):
        headers, owner_id = self.create_account("delete-me@example.test")
        with api.SessionLocal() as db:
            target = api.Target(
                owner_id=owner_id,
                url="https://example.test/v1/chat/completions",
                host="example.test",
                port=443,
                model="default",
                challenge_hash="test-challenge",
            )
            db.add(target)
            scan = api.Scan(
                owner_id=owner_id,
                target_id=None,
                company_name="Test Client",
                questionnaire={},
                status="completed",
                result_json={"summary": {}, "results": []},
            )
            db.add(scan)
            db.commit()
            target_id = target.id
            scan_id = scan.id

        response = self.client.delete("/api/me", headers=headers)
        self.assertEqual(response.status_code, 204, response.text)
        self.assertIn("max-age=0", response.headers.get("set-cookie", "").lower())
        self.assertEqual(self.client.get("/api/me", headers=headers).status_code, 401)
        with api.SessionLocal() as db:
            self.assertIsNone(db.query(api.User).filter(api.User.id == owner_id).first())
            self.assertIsNone(db.query(api.Target).filter(api.Target.id == target_id).first())
            self.assertIsNone(db.query(api.Scan).filter(api.Scan.id == scan_id).first())
            self.assertEqual(
                db.query(api.LoginSession)
                .filter(api.LoginSession.user_id == owner_id)
                .count(),
                0,
            )

    def test_account_deletion_is_blocked_while_a_scan_is_active(self):
        headers, owner_id = self.create_account("active-scan@example.test")
        with api.SessionLocal() as db:
            scan = api.Scan(
                owner_id=owner_id,
                target_id=None,
                company_name="Test Client",
                questionnaire={},
                status="running",
            )
            db.add(scan)
            db.commit()

        response = self.client.delete("/api/me", headers=headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.client.get("/api/me", headers=headers).status_code, 200)

    def test_logout_revokes_the_http_only_session(self):
        headers, _ = self.create_account("logout@example.test")
        response = self.client.post("/api/auth/logout", headers=headers)
        self.assertEqual(response.status_code, 204)
        self.assertIn("max-age=0", response.headers.get("set-cookie", "").lower())
        self.assertEqual(self.client.get("/api/me", headers=headers).status_code, 401)

    def test_production_configuration_fails_closed(self):
        with self.assertRaises(RuntimeError):
            api.validate_production_configuration(
                "production", "sqlite:///local.db", True, "judge-key"
            )
        with self.assertRaises(RuntimeError):
            api.validate_production_configuration(
                "production", "postgresql+psycopg://db", False, "judge-key"
            )
        with self.assertRaises(RuntimeError):
            api.validate_production_configuration(
                "production", "postgresql+psycopg://db", True, None
            )
        api.validate_production_configuration(
            "production", "postgresql+psycopg://db", True, "judge-key"
        )

    def test_retention_purges_only_expired_finished_scans_and_sessions(self):
        now = datetime(2026, 11, 15, 12, 0, 0)
        with api.SessionLocal() as db:
            user = api.User(
                email="retention@example.test",
                password_hash=api._password_hash("a-unique-password-123"),
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            old_finished = api.Scan(
                owner_id=user.id,
                company_name="Old finished scan",
                questionnaire={},
                status="completed",
                created_at=now - timedelta(days=31),
            )
            recent_finished = api.Scan(
                owner_id=user.id,
                company_name="Recent finished scan",
                questionnaire={},
                status="completed",
                created_at=now - timedelta(days=29),
            )
            old_running = api.Scan(
                owner_id=user.id,
                company_name="Old running scan",
                questionnaire={},
                status="running",
                created_at=now - timedelta(days=60),
            )
            db.add_all([old_finished, recent_finished, old_running])
            db.add_all([
                api.LoginSession(
                    user_id=user.id,
                    token_hash="expired-session-hash",
                    expires_at=now - timedelta(seconds=1),
                ),
                api.LoginSession(
                    user_id=user.id,
                    token_hash="active-session-hash",
                    expires_at=now + timedelta(days=1),
                ),
            ])
            db.commit()

            removed_scans, removed_sessions = maintenance.purge_expired_data(
                db, retention_days=30, now=now
            )
            self.assertEqual((removed_scans, removed_sessions), (1, 1))
            remaining_scans = db.query(api.Scan).filter(api.Scan.owner_id == user.id).all()
            self.assertEqual(
                {scan.company_name for scan in remaining_scans},
                {"Recent finished scan", "Old running scan"},
            )
            self.assertEqual(
                db.query(api.LoginSession)
                .filter(api.LoginSession.user_id == user.id)
                .count(),
                1,
            )

        with api.SessionLocal() as db:
            with self.assertRaises(ValueError):
                maintenance.purge_expired_data(db, retention_days=0, now=now)


if __name__ == "__main__":
    unittest.main()
