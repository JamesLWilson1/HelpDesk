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


    # --- Authentication edge cases ---

    def test_second_registered_user_is_regular_user(self):
        self.register("admin-user")
        response = self.register("normal-user")
        self.assertIn(b"Account created", response.data)
        response = self.login("normal-user")
        self.assertIn(b"My tickets", response.data)
        self.assertIn(b"normal-user (user)", response.data)

    def test_login_rejects_wrong_password(self):
        self.register("admin-user")
        response = self.login("admin-user", secret="wrongpassword")
        self.assertIn(b"Invalid username or password", response.data)

    def test_login_rejects_unknown_user(self):
        response = self.login("ghost")
        self.assertIn(b"Invalid username or password", response.data)

    def test_register_rejects_duplicate_username(self):
        self.register("admin-user")
        response = self.register("admin-user")
        self.assertIn(b"Username already exists", response.data)

    def test_register_rejects_invalid_username(self):
        token = self.csrf_token("/register")
        response = self.client.post(
            "/register",
            data={"csrf_token": token, "username": "bad user!", "password": "secret123"},
            follow_redirects=True,
        )
        self.assertIn(b"3-50 characters", response.data)

    # --- CSRF protection ---

    def test_post_without_csrf_token_returns_400(self):
        response = self.client.post(
            "/login",
            data={"username": "admin-user", "password": "secret123"},
        )
        self.assertEqual(response.status_code, 400)

    def test_post_with_wrong_csrf_token_returns_400(self):
        self.client.get("/login")  # establishes session with a real token
        response = self.client.post(
            "/login",
            data={"csrf_token": "wrong-token", "username": "admin-user", "password": "secret123"},
        )
        self.assertEqual(response.status_code, 400)

    # --- Access control ---

    def test_unauthenticated_user_redirected_to_login(self):
        for path in ["/dashboard", "/tickets/new", "/tickets/1"]:
            response = self.client.get(path, follow_redirects=False)
            self.assertEqual(response.status_code, 302, msg=f"{path} should redirect when unauthenticated")
            self.assertIn("/login", response.headers["Location"])

    def test_user_cannot_view_another_users_ticket(self):
        self.register("admin-user")
        self.register("user-one")
        self.register("user-two")
        self.login("user-one")
        self.create_ticket()
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("user-two")
        response = self.client.get("/tickets/1")
        self.assertEqual(response.status_code, 403)

    def test_user_cannot_edit_another_users_ticket(self):
        self.register("admin-user")
        self.register("user-one")
        self.register("user-two")
        self.login("user-one")
        self.create_ticket()
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("user-two")
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/edit",
            data={
                "csrf_token": token,
                "title": "Hacked",
                "description": "Hacked.",
                "category": "Hack",
                "priority": "low",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_user_cannot_use_admin_assign_route(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket()
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/assign",
            data={"csrf_token": token, "assigned_to": "1"},
        )
        self.assertEqual(response.status_code, 403)

    def test_user_cannot_use_admin_status_route(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket()
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/status",
            data={"csrf_token": token, "status": "closed", "resolution_notes": ""},
        )
        self.assertEqual(response.status_code, 403)

    def test_nonexistent_ticket_returns_404(self):
        self.register("admin-user")
        self.login("admin-user")
        response = self.client.get("/tickets/999")
        self.assertEqual(response.status_code, 404)

    # --- Input validation ---

    def test_ticket_creation_rejects_missing_fields(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/tickets/new")
        response = self.client.post(
            "/tickets/new",
            data={"csrf_token": token, "title": "", "description": "", "category": "", "priority": "low"},
            follow_redirects=True,
        )
        self.assertIn(b"required", response.data)

    def test_ticket_creation_rejects_long_title(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/tickets/new")
        response = self.client.post(
            "/tickets/new",
            data={
                "csrf_token": token,
                "title": "A" * 121,
                "description": "Some description.",
                "category": "Hardware",
                "priority": "low",
            },
            follow_redirects=True,
        )
        self.assertIn(b"120 characters", response.data)

    def test_comment_rejects_empty_body(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket()
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/comment",
            data={"csrf_token": token, "body": ""},
            follow_redirects=True,
        )
        self.assertIn(b"Comment cannot be empty", response.data)

    def test_comment_rejects_long_body(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket()
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/comment",
            data={"csrf_token": token, "body": "A" * 1001},
            follow_redirects=True,
        )
        self.assertIn(b"1000 characters", response.data)


if __name__ == "__main__":
    unittest.main()
