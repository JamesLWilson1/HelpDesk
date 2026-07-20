import os
import hashlib
import re
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta

import app as app_module
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

    def set_ticket_timestamps(self, ticket_id, created_at, updated_at=None, status=None):
        updated_at = updated_at or created_at
        query = "UPDATE tickets SET created_at = ?, updated_at = ?"
        params = [created_at.strftime("%Y-%m-%d %H:%M:%S"), updated_at.strftime("%Y-%m-%d %H:%M:%S")]
        if status:
            query += ", status = ?"
            params.append(status)
        query += " WHERE id = ?"
        params.append(ticket_id)
        db = sqlite3.connect(self.db_path)
        try:
            db.execute(query, tuple(params))
            db.commit()
        finally:
            db.close()

    def set_user_email(self, user_id, email):
        db = sqlite3.connect(self.db_path)
        try:
            db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
            db.commit()
        finally:
            db.close()

    def insert_password_reset_token(self, user_id, token, expires_at=None):
        expires_at = expires_at or datetime.utcnow() + timedelta(hours=1)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        db = sqlite3.connect(self.db_path)
        try:
            db.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, token_hash, expires_at.strftime("%Y-%m-%d %H:%M:%S")),
            )
            db.commit()
        finally:
            db.close()

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
        self.assertIn(b"We could not process that request", response.data)
        self.assertIn(b"Invalid CSRF token", response.data)

    def test_post_with_wrong_csrf_token_returns_400(self):
        self.client.get("/login")  # establishes session with a real token
        response = self.client.post(
            "/login",
            data={"csrf_token": "wrong-token", "username": "admin-user", "password": "secret123"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"We could not process that request", response.data)

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
        self.assertIn(b"You do not have access", response.data)

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
        self.assertIn(b"We could not find that page", response.data)

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

    def test_admin_can_add_internal_note(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket()

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/internal-notes",
            data={"csrf_token": token, "body": "Checked vendor warranty privately."},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Internal note added", response.data)
        self.assertIn(b"Checked vendor warranty privately", response.data)
        self.assertIn(b"Private troubleshooting notes", response.data)
        self.assertIn(b"Internal note added", response.data)

    def test_regular_user_cannot_add_internal_note(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket()

        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/internal-notes",
            data={"csrf_token": token, "body": "Should not work."},
        )

        self.assertEqual(response.status_code, 403)

    def test_regular_user_cannot_see_internal_notes(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket("User-visible ticket")
        self.post("/logout", {}, csrf_path="/dashboard")

        self.login("admin-user")
        token = self.dashboard_csrf()
        self.client.post(
            "/tickets/1/internal-notes",
            data={"csrf_token": token, "body": "Private admin diagnosis."},
            follow_redirects=True,
        )
        self.post("/logout", {}, csrf_path="/dashboard")

        self.login("normal-user")
        response = self.client.get("/tickets/1")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Internal Admin Notes", response.data)
        self.assertNotIn(b"Private admin diagnosis", response.data)

    # --- Ticket deletion ---

    def test_admin_can_delete_ticket(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket("To be deleted")
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("admin-user")
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/delete",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"Ticket deleted", response.data)
        self.assertNotIn(b"To be deleted", response.data)
        response = self.client.get("/tickets/1")
        self.assertEqual(response.status_code, 404)

    def test_user_cannot_delete_ticket(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket()
        token = self.dashboard_csrf()
        response = self.client.post(
            "/tickets/1/delete",
            data={"csrf_token": token},
        )
        self.assertEqual(response.status_code, 403)

    # --- Pagination ---

    def test_pagination_second_page_shows_older_tickets(self):
        import app as app_module
        original = app_module.PER_PAGE
        app_module.PER_PAGE = 2
        try:
            self.register("admin-user")
            self.login("admin-user")
            for i in range(1, 4):
                self.create_ticket(title=f"Ticket {i}")
            # Page 1 should show newest two (Ticket 3, Ticket 2)
            response = self.client.get("/dashboard?page=1")
            self.assertIn(b"Ticket 3", response.data)
            self.assertIn(b"Ticket 2", response.data)
            self.assertNotIn(b"Ticket 1", response.data)
            # Page 2 should show oldest one
            response = self.client.get("/dashboard?page=2")
            self.assertIn(b"Ticket 1", response.data)
            self.assertNotIn(b"Ticket 3", response.data)
        finally:
            app_module.PER_PAGE = original


    # --- User profile ---

    def test_user_can_update_email(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/profile")
        response = self.client.post(
            "/profile/email",
            data={"csrf_token": token, "email": "admin@example.com"},
            follow_redirects=True,
        )
        self.assertIn(b"Email updated", response.data)
        self.assertIn(b"admin@example.com", response.data)

    def test_user_can_change_password(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/profile")
        response = self.client.post(
            "/profile/password",
            data={"csrf_token": token, "current_password": "secret123", "new_password": "newpass456"},
            follow_redirects=True,
        )
        self.assertIn(b"Password updated", response.data)
        self.post("/logout", {}, csrf_path="/dashboard")
        response = self.login("admin-user", secret="newpass456")
        self.assertIn(b"All tickets", response.data)

    def test_change_password_rejects_wrong_current_password(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/profile")
        response = self.client.post(
            "/profile/password",
            data={"csrf_token": token, "current_password": "wrongpass", "new_password": "newpass456"},
            follow_redirects=True,
        )
        self.assertIn(b"Current password is incorrect", response.data)

    # --- Priority / category filters ---

    def test_dashboard_filters_by_priority_and_category(self):
        self.register("admin-user")
        self.login("admin-user")
        self.post(
            "/tickets/new",
            {"title": "High Hardware", "description": "desc", "category": "Hardware", "priority": "high"},
            csrf_path="/tickets/new",
        )
        self.post(
            "/tickets/new",
            {"title": "Low Software", "description": "desc", "category": "Software", "priority": "low"},
            csrf_path="/tickets/new",
        )
        response = self.client.get("/dashboard?priority=high")
        self.assertIn(b"High Hardware", response.data)
        self.assertNotIn(b"Low Software", response.data)

        response = self.client.get("/dashboard?category=Software")
        self.assertIn(b"Low Software", response.data)
        self.assertNotIn(b"High Hardware", response.data)

    # --- Audit log ---

    def test_audit_log_records_ticket_lifecycle(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket("Audit test ticket")
        self.post("/logout", {}, csrf_path="/dashboard")

        self.login("admin-user")
        token = self.dashboard_csrf()
        self.client.post(
            "/tickets/1/status",
            data={"csrf_token": token, "status": "in_progress", "resolution_notes": ""},
            follow_redirects=True,
        )
        token = self.dashboard_csrf()
        self.client.post(
            "/tickets/1/assign",
            data={"csrf_token": token, "assigned_to": "1"},
            follow_redirects=True,
        )

        response = self.client.get("/tickets/1")
        self.assertIn(b"Ticket created", response.data)
        self.assertIn(b"Status changed from open to in_progress", response.data)
        self.assertIn(b"Assigned to admin-user", response.data)

    # --- Admin user management ---

    def test_admin_can_view_users_list(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("admin-user")
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"admin-user", response.data)
        self.assertIn(b"normal-user", response.data)

    def test_admin_can_promote_and_demote_user(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("admin-user")
        token = self.csrf_token("/admin/users")
        response = self.client.post(
            "/admin/users/2/role",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"admin", response.data)
        # Demote back
        token = self.csrf_token("/admin/users")
        self.client.post("/admin/users/2/role", data={"csrf_token": token}, follow_redirects=True)

    def test_admin_cannot_demote_last_admin(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/admin/users")
        response = self.client.post(
            "/admin/users/1/role",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"cannot change your own role", response.data)

    def test_admin_can_reset_user_password(self):
        self.register("admin-user")
        self.register("normal-user")
        self.set_user_email(2, "normal@example.com")
        self.app.config["MAIL_DEFAULT_SENDER"] = "helpdesk@example.com"
        self.login("admin-user")
        token = self.csrf_token("/admin/users")
        response = self.client.post(
            "/admin/users/2/password",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"Password reset link sent to normal-user.", response.data)
        self.assertNotIn(b"reset to:", response.data)

        db = sqlite3.connect(self.db_path)
        try:
            count = db.execute("SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = 2").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(count, 1)

    def test_admin_password_reset_email_contains_one_time_link(self):
        self.register("admin-user")
        self.register("normal-user")
        self.set_user_email(2, "normal@example.com")
        self.app.config["MAIL_DEFAULT_SENDER"] = "helpdesk@example.com"
        self.app.config["MAIL_TEST_OUTBOX"] = []
        self.login("admin-user")

        token = self.csrf_token("/admin/users")
        response = self.client.post(
            "/admin/users/2/password",
            data={"csrf_token": token},
            follow_redirects=True,
        )

        self.assertIn(b"Password reset link sent to normal-user.", response.data)
        outbox = self.app.config["MAIL_TEST_OUTBOX"]
        self.assertEqual(len(outbox), 1)
        message = outbox[0]
        self.assertEqual(message.subject, "[HelpDesk] Password reset link")
        self.assertEqual(message.recipients, ["normal@example.com"])
        self.assertIn("This link expires in 1 hour", message.body)

        link_match = re.search(r"/reset-password/([^\s]+)", message.body)
        self.assertIsNotNone(link_match)
        reset_token = link_match.group(1)
        token_hash = hashlib.sha256(reset_token.encode("utf-8")).hexdigest()

        db = sqlite3.connect(self.db_path)
        try:
            stored = db.execute(
                "SELECT token_hash FROM password_reset_tokens WHERE user_id = 2"
            ).fetchone()[0]
        finally:
            db.close()
        self.assertEqual(stored, token_hash)

    def test_admin_password_reset_requires_email_configuration(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("admin-user")

        response = self.post("/admin/users/2/password", {}, csrf_path="/admin/users")

        self.assertIn(b"Add an email address", response.data)

    def test_password_reset_token_updates_password_once(self):
        self.register("admin-user")
        token = "valid-reset-token"
        self.insert_password_reset_token(1, token)

        csrf_token = self.csrf_token(f"/reset-password/{token}")
        response = self.client.post(
            f"/reset-password/{token}",
            data={"csrf_token": csrf_token, "new_password": "newpass456"},
            follow_redirects=True,
        )

        self.assertIn(b"Password updated", response.data)
        response = self.login("admin-user", secret="newpass456")
        self.assertIn(b"All tickets", response.data)

        response = self.client.get(f"/reset-password/{token}", follow_redirects=True)
        self.assertIn(b"invalid or expired", response.data)

    def test_ticket_summary_route_is_rate_limited(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket("Rate limit summary")

        first = self.client.get("/tickets/1/summary")
        second = self.client.get("/tickets/1/summary")
        third = self.client.get("/tickets/1/summary")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 429)

    def test_admin_cannot_delete_user_with_tickets(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        self.create_ticket()
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("admin-user")
        token = self.csrf_token("/admin/users")
        response = self.client.post(
            "/admin/users/2/delete",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertIn(b"ticket(s)", response.data)

    def test_user_cannot_access_admin_users_page(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 403)

    # --- Ticket sorting ---

    def test_dashboard_sort_by_priority(self):
        self.register("admin-user")
        self.login("admin-user")
        self.post(
            "/tickets/new",
            {"title": "Low ticket", "description": "d", "category": "General", "priority": "low"},
            csrf_path="/tickets/new",
        )
        self.post(
            "/tickets/new",
            {"title": "High ticket", "description": "d", "category": "General", "priority": "high"},
            csrf_path="/tickets/new",
        )
        response = self.client.get("/dashboard?sort=priority_high")
        high_pos = response.data.index(b"High ticket")
        low_pos = response.data.index(b"Low ticket")
        self.assertLess(high_pos, low_pos)

    def test_dashboard_shows_sla_breached_filter(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket("Breached SLA")
        self.create_ticket("Fresh SLA")
        self.set_ticket_timestamps(1, datetime.utcnow() - timedelta(hours=5))

        response = self.client.get("/dashboard?sla=breached")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Breached SLA", response.data)
        self.assertIn(b"SLA breached", response.data)
        self.assertIn(b"Overdue by", response.data)
        self.assertNotIn(b"Fresh SLA", response.data)

    def test_dashboard_shows_sla_at_risk_status(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket("At Risk SLA")
        self.set_ticket_timestamps(1, datetime.utcnow() - timedelta(hours=3, minutes=30))

        response = self.client.get("/dashboard?sla=at_risk")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"At Risk SLA", response.data)
        self.assertIn(b"SLA at risk", response.data)
        self.assertIn(b"Target 4h", response.data)

    def test_ticket_detail_shows_resolved_sla_status(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket("Resolved SLA")
        created_at = datetime.utcnow() - timedelta(hours=1)
        self.set_ticket_timestamps(1, created_at, created_at + timedelta(minutes=30), status="closed")

        response = self.client.get("/tickets/1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Resolved within SLA", response.data)
        self.assertIn(b"Target 4h", response.data)

    # --- CSV export ---

    def test_admin_can_export_csv(self):
        self.register("admin-user")
        self.login("admin-user")
        self.create_ticket("Export test")
        response = self.client.get("/admin/export/tickets.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"text/csv", response.content_type.encode())
        self.assertIn(b"Export test", response.data)
        self.assertIn(b"title", response.data)

    def test_user_cannot_export_csv(self):
        self.register("admin-user")
        self.register("normal-user")
        self.login("normal-user")
        response = self.client.get("/admin/export/tickets.csv")
        self.assertEqual(response.status_code, 403)

    # --- Due dates ---

    def test_ticket_due_date_is_stored_and_shown(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/tickets/new")
        self.client.post(
            "/tickets/new",
            data={
                "csrf_token": token,
                "title": "Due date ticket",
                "description": "Test",
                "category": "General",
                "priority": "high",
                "due_date": "2030-12-31",
            },
            follow_redirects=True,
        )
        response = self.client.get("/tickets/1")
        self.assertIn(b"2030-12-31", response.data)

    def test_overdue_ticket_highlighted_on_dashboard(self):
        self.register("admin-user")
        self.login("admin-user")
        token = self.csrf_token("/tickets/new")
        self.client.post(
            "/tickets/new",
            data={
                "csrf_token": token,
                "title": "Overdue ticket",
                "description": "Test",
                "category": "General",
                "priority": "high",
                "due_date": "2000-01-01",
            },
            follow_redirects=True,
        )
        response = self.client.get("/dashboard")
        self.assertIn(b"ticket-overdue", response.data)

    def test_dashboard_displays_stats_chart(self):
        self.register("alice")
        self.login("alice")
        self.create_ticket("Issue 1")
        response = self.client.get("/dashboard")
        # Check that the chart container and heading are present
        self.assertIn(b"Ticket Status Overview", response.data)
        self.assertIn(b'id="statsChart"', response.data)
        # Check that Chart.js is loaded
        self.assertIn(b"chart.js", response.data)

    def test_search_page_loads(self):
        self.register("alice")
        self.login("alice")
        response = self.client.get("/search")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Advanced Search", response.data)
        self.assertIn(b"Keywords", response.data)
        self.assertIn(b"Status", response.data)
        self.assertIn(b"Priority", response.data)

    def test_search_requires_login(self):
        response = self.client.get("/search")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_search_by_keywords(self):
        self.register("alice")
        self.login("alice")
        self.post("/tickets/new", {"title": "Hardware Problem", "description": "Desktop not working", "category": "Hardware", "priority": "medium"}, csrf_path="/tickets/new")
        self.post("/tickets/new", {"title": "Software Bug", "description": "App crashes", "category": "Software", "priority": "medium"}, csrf_path="/tickets/new")
        response = self.client.get("/search?keywords=hardware")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hardware Problem", response.data)
        self.assertNotIn(b"Software Bug", response.data)
        self.assertIn(b"Found 1 ticket", response.data)

    def test_search_by_status(self):
        self.register("alice")
        self.login("alice")
        self.create_ticket("Test Ticket")
        # Update ticket status to closed (admin-only route)
        token = self.dashboard_csrf()
        self.client.post(
            "/tickets/1/status",
            data={"csrf_token": token, "status": "closed"},
        )
        response = self.client.get("/search?status=closed")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test Ticket", response.data)
        self.assertIn(b"Found 1 ticket", response.data)

    def test_search_by_priority(self):
        self.register("alice")
        self.login("alice")
        self.post("/tickets/new", {"title": "High Priority", "description": "Urgent", "category": "Other", "priority": "high"}, csrf_path="/tickets/new")
        response = self.client.get("/search?priority=high")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"High Priority", response.data)

    def test_search_by_category(self):
        self.register("alice")
        self.login("alice")
        self.post("/tickets/new", {"title": "Hardware Issue", "description": "Test", "category": "Hardware", "priority": "medium"}, csrf_path="/tickets/new")
        self.post("/tickets/new", {"title": "Network Issue", "description": "Test", "category": "Network", "priority": "medium"}, csrf_path="/tickets/new")
        response = self.client.get("/search?category=Hardware")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hardware Issue", response.data)
        self.assertNotIn(b"Network Issue", response.data)

    def test_search_by_assigned_to(self):
        self.register("admin-user")  # First user becomes admin
        self.login("admin-user")
        self.create_ticket("Assigned Ticket")
        # Assign ticket to admin-user (id=1)
        token = self.dashboard_csrf()
        self.client.post(
            "/tickets/1/assign",
            data={"csrf_token": token, "assigned_to": "1"},
        )
        # Search for tickets assigned to admin-user
        response = self.client.get("/search?assigned_to=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Assigned Ticket", response.data)

    def test_search_by_created_by(self):
        self.register("alice")
        self.register("bob")
        self.login("alice")
        self.create_ticket("Alice Ticket")
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("bob")
        self.create_ticket("Bob Ticket")
        # Alice's ID is 1
        alice_id = 1
        response = self.client.get(f"/search?created_by={alice_id}")
        self.assertEqual(response.status_code, 200)
        # Bob can't see Alice's ticket (non-admin)
        self.assertNotIn(b"Alice Ticket", response.data)

    def test_search_by_date_range(self):
        self.register("alice")
        self.login("alice")
        self.create_ticket("Recent Ticket")
        db = sqlite3.connect(self.db_path)
        try:
            created_date = db.execute("SELECT DATE(created_at) FROM tickets WHERE id = 1").fetchone()[0]
        finally:
            db.close()
        response = self.client.get(f"/search?created_from={created_date}&created_to={created_date}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Recent Ticket", response.data)

    def test_search_combined_filters(self):
        self.register("alice")
        self.login("alice")
        self.create_ticket("Hardware High")  # Default category is Hardware
        self.post("/tickets/new", {"title": "Hardware Low", "description": "Test", "category": "Hardware", "priority": "low"}, csrf_path="/tickets/new")
        response = self.client.get("/search?category=Hardware&priority=low")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hardware Low", response.data)
        self.assertNotIn(b"Hardware High", response.data)

    def test_search_non_admin_sees_own_tickets_only(self):
        self.register("alice")
        self.register("bob")
        self.login("alice")
        self.create_ticket("Alice Ticket")
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("bob")
        self.create_ticket("Bob Ticket")
        response = self.client.get("/search?keywords=ticket")
        self.assertEqual(response.status_code, 200)
        # Bob should only see their own ticket
        self.assertIn(b"Bob Ticket", response.data)
        self.assertNotIn(b"Alice Ticket", response.data)

    def test_search_admin_sees_all_tickets(self):
        self.register("admin-user")  # First user becomes admin
        self.register("alice")
        self.login("alice")
        self.create_ticket("Alice Ticket")
        self.post("/logout", {}, csrf_path="/dashboard")
        self.login("admin-user")
        self.create_ticket("Admin Ticket")
        response = self.client.get("/search?keywords=ticket")
        self.assertEqual(response.status_code, 200)
        # Admin should see all tickets
        self.assertIn(b"Alice Ticket", response.data)
        self.assertIn(b"Admin Ticket", response.data)

    # Notification system tests
    def test_notification_created_on_new_ticket(self):
        """Admins should receive notifications when a new ticket is created."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        response = self.create_ticket("Test Ticket")
        self.assertEqual(response.status_code, 200)
        # Login as admin and check notifications
        self.login("admin1")
        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"New ticket submitted by user1: Test Ticket", response.data)

    def test_notification_created_on_assignment(self):
        """Assigned user should receive notification when ticket is assigned."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Assignment Test")
        # Promote user1 to admin so they can be assigned
        self.login("admin1")
        self.post("/admin/users/2/role", {}, csrf_path="/admin/users")  # Promote user1 to admin
        # Assign ticket to user1
        self.post("/tickets/1/assign", {"assigned_to": "2"}, csrf_path="/tickets/1")
        # Login as user1 and check notifications
        self.login("user1")
        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ticket #1 (Assignment Test) has been assigned to you", response.data)

    def test_notification_created_on_comment(self):
        """Ticket owner should receive notification when someone comments."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Comment Test")
        self.login("admin1")
        # Comment on the ticket
        self.post("/tickets/1/comment", {"body": "This is a test comment"}, csrf_path="/tickets/1")
        # Login as user1 and check notifications
        self.login("user1")
        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"New comment on ticket #1 (Comment Test) by admin1", response.data)

    def test_notification_created_on_status_change(self):
        """Ticket owner should receive notification when status changes."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Status Test")
        self.login("admin1")
        # Change status
        self.post("/tickets/1/status", {"status": "in_progress"}, csrf_path="/tickets/1")
        # Login as user1 and check notifications
        self.login("user1")
        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Ticket #1 (Status Test) status changed to in_progress", response.data)

    def test_mark_notification_read(self):
        """Users should be able to mark individual notifications as read."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Mark Read Test")
        self.login("admin1")
        # Get notification ID
        response = self.client.get("/notifications")
        self.assertIn(b"New ticket submitted", response.data)
        # Mark as read
        self.post("/notifications/mark-read/1", {}, csrf_path="/notifications")
        response = self.client.get("/notifications")
        # Notification should still be there but not marked as unread
        self.assertNotIn(b'class="notification-item unread"', response.data)

    def test_mark_all_notifications_read(self):
        """Users should be able to mark all notifications as read."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Test 1")
        self.create_ticket("Test 2")
        self.login("admin1")
        # Check we have unread notifications
        response = self.client.get("/notifications")
        self.assertIn(b"New ticket submitted", response.data)
        # Mark all as read
        self.post("/notifications/mark-all-read", {}, csrf_path="/notifications")
        response = self.client.get("/notifications")
        # Should not have unread class anymore
        self.assertNotIn(b'class="notification-item unread"', response.data)

    def test_notification_visibility(self):
        """Users should only see their own notifications."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("User1 Ticket")
        self.login("admin1")
        # Admin has notification
        response = self.client.get("/notifications")
        self.assertIn(b"New ticket submitted by user1", response.data)
        # User1 should not have any notifications (they created the ticket)
        self.login("user1")
        response = self.client.get("/notifications")
        # User1 didn't receive any notifications, so should have none
        self.assertIn(b"You have no notifications", response.data)

    def test_email_preferences_update(self):
        """Users should be able to update their email notification preferences."""
        self.register("user1")  # First user becomes admin
        self.login("user1")
        # Update preferences
        response = self.post(
            "/profile/notifications",
            {
                "email_on_assign": "on",
                "email_on_comment": "on",
                "email_on_status": "",
            },
            csrf_path="/profile"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Notification preferences updated", response.data)

    def test_unread_notification_count_in_header(self):
        """Unread notification count should appear in header."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Count Test")
        self.login("admin1")
        # Check dashboard for notification count
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        # Should have notification badge with count
        self.assertIn(b"notification-badge", response.data)
        self.assertIn(b">1<", response.data)  # Badge should show 1 unread

    def test_session_cookie_security_defaults(self):
        """App should default to safer session cookie settings."""
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertFalse(self.app.config["SESSION_COOKIE_SECURE"])

    def test_session_cookie_secure_defaults_to_true_in_production(self):
        """Production environments should default to secure session cookies."""
        previous_app_env = os.environ.get("APP_ENV")
        previous_cookie_secure = os.environ.get("SESSION_COOKIE_SECURE")
        os.environ["APP_ENV"] = "production"
        os.environ.pop("SESSION_COOKIE_SECURE", None)
        try:
            production_app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test-secret",
                    "DATABASE": os.path.join(self.temp_dir.name, "production-test.sqlite"),
                }
            )
            self.assertTrue(production_app.config["SESSION_COOKIE_SECURE"])
        finally:
            if previous_app_env is None:
                os.environ.pop("APP_ENV", None)
            else:
                os.environ["APP_ENV"] = previous_app_env
            if previous_cookie_secure is None:
                os.environ.pop("SESSION_COOKIE_SECURE", None)
            else:
                os.environ["SESSION_COOKIE_SECURE"] = previous_cookie_secure

    def test_session_cookie_secure_env_override(self):
        """Explicit SESSION_COOKIE_SECURE value should override environment default."""
        previous_app_env = os.environ.get("APP_ENV")
        previous_cookie_secure = os.environ.get("SESSION_COOKIE_SECURE")
        os.environ["APP_ENV"] = "production"
        os.environ["SESSION_COOKIE_SECURE"] = "false"
        try:
            override_app = create_app(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test-secret",
                    "DATABASE": os.path.join(self.temp_dir.name, "override-test.sqlite"),
                }
            )
            self.assertFalse(override_app.config["SESSION_COOKIE_SECURE"])
        finally:
            if previous_app_env is None:
                os.environ.pop("APP_ENV", None)
            else:
                os.environ["APP_ENV"] = previous_app_env
            if previous_cookie_secure is None:
                os.environ.pop("SESSION_COOKIE_SECURE", None)
            else:
                os.environ["SESSION_COOKIE_SECURE"] = previous_cookie_secure

    def test_notification_link_to_ticket(self):
        """Notifications should link to the relevant ticket."""
        self.register("admin1")  # First user becomes admin
        self.register("user1")
        self.login("user1")
        self.create_ticket("Link Test")
        self.login("admin1")
        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 200)
        # Should have link to ticket #1
        self.assertIn(b"/tickets/1", response.data)

    def test_mark_notification_read_rejects_external_referrer_redirect(self):
        """Mark-read should never redirect to external hosts from the Referer header."""
        self.register("admin1")
        self.register("user1")
        self.login("user1")
        self.create_ticket("Referrer Safety")
        self.login("admin1")

        token = self.csrf_token("/notifications")
        response = self.client.post(
            "/notifications/mark-read/1",
            data={"csrf_token": token},
            headers={"Referer": "https://evil.example/phish"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/notifications", response.headers["Location"])
        self.assertNotIn("evil.example", response.headers["Location"])

    # File upload enhancement tests
    def test_multiple_file_upload(self):
        """Users should be able to upload multiple files at once."""
        import io
        self.register("user1")
        self.login("user1")
        self.create_ticket("Multi Upload Test")
        
        # Create multiple test files
        token = self.dashboard_csrf()
        data = {
            'csrf_token': token,
            'file': [
                (io.BytesIO(b'test content 1'), 'test1.txt'),
                (io.BytesIO(b'test content 2'), 'test2.txt'),
            ]
        }
        
        response = self.client.post(
            '/tickets/1/attachments',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'file(s) uploaded successfully', response.data)
        self.assertIn(b'test1.txt', response.data)
        self.assertIn(b'test2.txt', response.data)
        self.assertIn(b'Attachment library', response.data)
        self.assertIn(b'Uploaded by user1', response.data)
        self.assertIn(b'Download', response.data)

    def test_file_upload_with_invalid_type(self):
        """Invalid file types should be rejected."""
        import io
        self.register("user1")
        self.login("user1")
        self.create_ticket("Invalid Upload Test")
        
        token = self.dashboard_csrf()
        data = {
            'csrf_token': token,
            'file': [(io.BytesIO(b'fake exe'), 'virus.exe')]
        }
        
        response = self.client.post(
            '/tickets/1/attachments',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'invalid file type', response.data)

    def test_large_file_upload_shows_friendly_error(self):
        """Files over the app limit should show the friendly 413 page."""
        import io
        self.register("user1")
        self.login("user1")
        self.create_ticket("Large Upload Test")
        self.app.config["MAX_CONTENT_LENGTH"] = None
        original_max_file_bytes = app_module.MAX_FILE_BYTES
        app_module.MAX_FILE_BYTES = 5

        token = self.dashboard_csrf()
        data = {
            'csrf_token': token,
            'file': [(io.BytesIO(b'x' * 6), 'large.txt')]
        }

        try:
            response = self.client.post(
                '/tickets/1/attachments',
                data=data,
                content_type='multipart/form-data',
            )
        finally:
            app_module.MAX_FILE_BYTES = original_max_file_bytes

        self.assertEqual(response.status_code, 413)
        self.assertIn(b'That file is too large', response.data)
        self.assertIn(b'Attachments must be 5 MB or smaller', response.data)

    def test_mixed_valid_invalid_files(self):
        """Valid files should upload even when mixed with invalid ones."""
        import io
        self.register("user1")
        self.login("user1")
        self.create_ticket("Mixed Upload Test")
        
        token = self.dashboard_csrf()
        data = {
            'csrf_token': token,
            'file': [
                (io.BytesIO(b'valid content'), 'valid.txt'),
                (io.BytesIO(b'invalid content'), 'invalid.exe'),
            ]
        }
        
        response = self.client.post(
            '/tickets/1/attachments',
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'1 file(s) uploaded successfully', response.data)
        self.assertIn(b'valid.txt', response.data)

    # Template tests
    def test_admin_can_create_template(self):
        """Admins should be able to create ticket templates."""
        self.register("admin1")
        self.login("admin1")
        
        response = self.post(
            "/admin/templates/new",
            {
                "name": "Password Reset",
                "description": "User cannot access their account",
                "category": "Software",
                "priority": "medium",
                "default_title": "Cannot access my account",
                "default_description": "I am unable to log in to my account. Please reset my password.",
            },
            csrf_path="/admin/templates/new"
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Template created successfully', response.data)
        self.assertIn(b'Password Reset', response.data)

    def test_user_cannot_create_template(self):
        """Regular users should not be able to create templates."""
        self.register("admin1")
        self.register("user1")
        self.login("user1")
        
        response = self.client.get("/admin/templates/new")
        self.assertEqual(response.status_code, 403)

    def test_template_appears_on_dashboard(self):
        """Active templates should appear on the dashboard."""
        self.register("admin1")
        self.login("admin1")
        
        # Create a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Printer Issue",
                "description": "Printer problems",
                "category": "Hardware",
                "priority": "low",
                "default_title": "Printer not working",
                "default_description": "The printer is not responding.",
            },
            csrf_path="/admin/templates/new"
        )
        
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Printer Issue', response.data)
        self.assertIn(b'Quick Create from Template', response.data)

    def test_ticket_created_from_template(self):
        """Tickets created from templates should have pre-filled values."""
        self.register("admin1")
        self.login("admin1")
        
        # Create a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Email Problem",
                "description": "Email access issues",
                "category": "Software",
                "priority": "high",
                "default_title": "Cannot send emails",
                "default_description": "I am unable to send emails from my account.",
            },
            csrf_path="/admin/templates/new"
        )
        
        # Access the create ticket page with template
        response = self.client.get("/tickets/new?template_id=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Cannot send emails', response.data)
        self.assertIn(b'unable to send emails', response.data)
        self.assertIn(b'Using template: Email Problem', response.data)

    def test_admin_can_edit_template(self):
        """Admins should be able to edit templates."""
        self.register("admin1")
        self.login("admin1")
        
        # Create a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Original Name",
                "description": "Original description",
                "category": "Software",
                "priority": "low",
                "default_title": "Original title",
                "default_description": "Original description text.",
            },
            csrf_path="/admin/templates/new"
        )
        
        # Edit the template
        response = self.post(
            "/admin/templates/1/edit",
            {
                "name": "Updated Name",
                "description": "Updated description",
                "category": "Hardware",
                "priority": "high",
                "default_title": "Updated title",
                "default_description": "Updated description text.",
            },
            csrf_path="/admin/templates/1/edit"
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Template updated successfully', response.data)
        self.assertIn(b'Updated Name', response.data)

    def test_admin_can_toggle_template(self):
        """Admins should be able to activate/deactivate templates."""
        self.register("admin1")
        self.login("admin1")
        
        # Create a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Toggle Test",
                "description": "Test template",
                "category": "Software",
                "priority": "medium",
                "default_title": "Test",
                "default_description": "Test description.",
            },
            csrf_path="/admin/templates/new"
        )
        
        # Deactivate the template
        response = self.post("/admin/templates/1/toggle", {}, csrf_path="/admin/templates")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'deactivated', response.data)
        
        # Template should not appear on dashboard when inactive
        response = self.client.get("/dashboard")
        self.assertNotIn(b'Toggle Test', response.data)

    def test_admin_can_delete_template(self):
        """Admins should be able to delete templates."""
        self.register("admin1")
        self.login("admin1")
        
        # Create a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Delete Test",
                "description": "Will be deleted",
                "category": "Software",
                "priority": "low",
                "default_title": "Test",
                "default_description": "Test.",
            },
            csrf_path="/admin/templates/new"
        )
        
        # Delete the template
        response = self.post("/admin/templates/1/delete", {}, csrf_path="/admin/templates")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Template deleted', response.data)
        self.assertNotIn(b'Delete Test', response.data)

    def test_inactive_template_not_usable(self):
        """Inactive templates should not be usable for creating tickets."""
        self.register("admin1")
        self.login("admin1")
        
        # Create and deactivate a template
        self.post(
            "/admin/templates/new",
            {
                "name": "Inactive Test",
                "description": "Test",
                "category": "Software",
                "priority": "medium",
                "default_title": "Test",
                "default_description": "Test.",
            },
            csrf_path="/admin/templates/new"
        )
        self.post("/admin/templates/1/toggle", {}, csrf_path="/admin/templates")
        
        # Try to use the inactive template
        response = self.client.get("/tickets/new?template_id=1")
        self.assertEqual(response.status_code, 200)
        # Should not show template data
        self.assertNotIn(b'Using template:', response.data)


if __name__ == "__main__":
    unittest.main()
