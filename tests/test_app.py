import os
import tempfile
import unittest

from app import create_app


class HelpDeskAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test.sqlite")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": self.db_path,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def post(self, path, data, follow_redirects=True, csrf_path=None):
        token = self.csrf_token(csrf_path or path)
        payload = dict(data)
        payload["csrf_token"] = token
        return self.client.post(path, data=payload, follow_redirects=follow_redirects)

    def register(self, username, secret="secret123"):
        return self.post("/register", {"username": username, "password": secret}, csrf_path="/register")

    def login(self, username, secret="secret123"):
        return self.post("/login", {"username": username, "password": secret}, csrf_path="/login")

    def create_ticket(self, title="Printer issue"):
        return self.post(
            "/tickets/new",
            {
                "title": title,
                "description": "Office printer is jammed.",
                "category": "Hardware",
                "priority": "high",
            },
            csrf_path="/tickets/new",
        )

    def dashboard_csrf(self):
        self.client.get("/dashboard")
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def test_first_registered_user_becomes_admin(self):
        response = self.register("admin-user")
        self.assertIn(b"Account created", response.data)

        response = self.login("admin-user")
        self.assertIn(b"All tickets", response.data)
        self.assertIn(b"admin-user (admin)", response.data)

    def test_user_can_create_view_edit_and_comment_on_own_ticket(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")

        response = self.create_ticket()
        self.assertIn(b"Ticket created successfully", response.data)
        self.assertIn(b"Printer issue", response.data)

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/edit",
            data={
                "csrf_token": token,
                "title": "Printer issue updated",
                "description": "Printer still jammed after restart.",
                "category": "Hardware",
                "priority": "medium",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Ticket updated successfully", response.data)

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/comment",
            data={"csrf_token": token, "body": "Please help soon."},
            follow_redirects=True,
        )
        self.assertIn(b"Comment added", response.data)
        self.assertIn(b"Please help soon.", response.data)

    def test_admin_can_filter_assign_and_close_ticket(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket("VPN access")
        self.post("/logout", {}, csrf_path="/dashboard")

        self.login("admin-user")
        response = self.client.get("/dashboard?status=open&search=VPN")
        self.assertIn(b"VPN access", response.data)

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/assign",
            data={"csrf_token": token, "assigned_to": "1"},
            follow_redirects=True,
        )
        self.assertIn(b"Ticket assignment updated", response.data)
        self.assertIn(b"Assigned to: admin-user", response.data)

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/status",
            data={
                "csrf_token": token,
                "status": "closed",
                "resolution_notes": "VPN profile was refreshed.",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Ticket status updated", response.data)
        self.assertIn(b"VPN profile was refreshed.", response.data)
        self.assertIn(b"Status: closed", response.data)


if __name__ == "__main__":
    unittest.main()
