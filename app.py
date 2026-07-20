import csv
import hashlib
import io
import os
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from functools import wraps

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
if OPENAI_AVAILABLE:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
else:
    client = None

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
MAX_TITLE_LENGTH = 120
MAX_CATEGORY_LENGTH = 60
MAX_DESCRIPTION_LENGTH = 2000
MAX_COMMENT_LENGTH = 1000
PER_PAGE = 20
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".csv", ".gif", ".jpeg", ".jpg", ".log", ".pdf", ".png", ".txt", ".webp"}
SLA_TARGET_HOURS = {"high": 4, "medium": 24, "low": 72}
SORT_OPTIONS = {
    "updated_desc": "tickets.updated_at DESC, tickets.id DESC",
    "updated_asc": "tickets.updated_at ASC, tickets.id ASC",
    "created_desc": "tickets.created_at DESC, tickets.id DESC",
    "created_asc": "tickets.created_at ASC, tickets.id ASC",
    "priority_high": "CASE tickets.priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END ASC, tickets.updated_at DESC",
    "priority_low": "CASE tickets.priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END DESC, tickets.updated_at DESC",
    "due_asc": "COALESCE(tickets.due_date, '9999-12-31') ASC, tickets.id DESC",
    "due_desc": "COALESCE(tickets.due_date, '') DESC, tickets.id DESC",
}


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def is_production_env():
    return os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "")).lower() in {"prod", "production"}


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.path.join(app.instance_path, "helpdesk.sqlite"),
        MAIL_SERVER=os.environ.get("MAIL_SERVER", "localhost"),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "true").lower() == "true",
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER"),
        MAX_CONTENT_LENGTH=MAX_FILE_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", default=is_production_env()),
    )

    if test_config is not None:
        app.config.update(test_config)

    mail = Mail(app)
    limiter = Limiter(key_func=get_remote_address, app=app, storage_uri="memory://")
    os.makedirs(app.instance_path, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    def close_db(_error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = sqlite3.connect(app.config["DATABASE"])
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
                email TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high')),
                status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'closed')),
                resolution_notes TEXT NOT NULL DEFAULT '',
                user_id INTEGER NOT NULL,
                assigned_to INTEGER,
                due_date TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (assigned_to) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS internal_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                FOREIGN KEY (user_id) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                ticket_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (ticket_id) REFERENCES tickets (id)
            );

            CREATE TABLE IF NOT EXISTS ticket_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                priority TEXT NOT NULL CHECK (priority IN ('low', 'medium', 'high')),
                default_title TEXT NOT NULL,
                default_description TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            """
        )
        db.commit()
        # Migrate: add email column to existing databases
        try:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
            db.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Migrate: add due_date column to existing databases
        try:
            db.execute("ALTER TABLE tickets ADD COLUMN due_date TEXT")
            db.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Migrate: add email preference columns
        try:
            db.execute("ALTER TABLE users ADD COLUMN email_on_assign INTEGER NOT NULL DEFAULT 1")
            db.commit()
        except sqlite3.OperationalError:
            pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN email_on_comment INTEGER NOT NULL DEFAULT 1")
            db.commit()
        except sqlite3.OperationalError:
            pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN email_on_status INTEGER NOT NULL DEFAULT 1")
            db.commit()
        except sqlite3.OperationalError:
            pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN email_on_new_ticket INTEGER NOT NULL DEFAULT 1")
            db.commit()
        except sqlite3.OperationalError:
            pass
        db.close()

    def query_one(query, params=()):
        return get_db().execute(query, params).fetchone()

    def query_all(query, params=()):
        return get_db().execute(query, params).fetchall()

    def execute(query, params=()):
        db = get_db()
        cursor = db.execute(query, params)
        db.commit()
        return cursor

    def new_csrf_token():
        session["_csrf_token"] = session.get("_csrf_token") or secrets.token_hex(16)
        return session["_csrf_token"]

    def rotate_csrf_token():
        session["_csrf_token"] = secrets.token_hex(16)
        return session["_csrf_token"]

    def validate_csrf():
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("_csrf_token"):
            abort(400, "Invalid CSRF token.")

    def escape_like(term):
        return term.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")

    def validate_ticket_fields(title, description, category):
        if not title or not description or not category:
            return "Title, description, and category are required."
        if len(title) > MAX_TITLE_LENGTH:
            return f"Title must be {MAX_TITLE_LENGTH} characters or fewer."
        if len(category) > MAX_CATEGORY_LENGTH:
            return f"Category must be {MAX_CATEGORY_LENGTH} characters or fewer."
        if len(description) > MAX_DESCRIPTION_LENGTH:
            return f"Description must be {MAX_DESCRIPTION_LENGTH} characters or fewer."
        return None

    def uploaded_file_size(file):
        file.stream.seek(0, os.SEEK_END)
        size = file.stream.tell()
        file.stream.seek(0)
        return size

    def parse_timestamp(value):
        if isinstance(value, datetime):
            return value
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except (TypeError, ValueError):
                continue
        return datetime.utcnow()

    def hash_reset_token(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_password_reset_token(user_id):
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, hash_reset_token(token), expires_at),
        )
        return token

    def get_valid_password_reset(token):
        reset = query_one(
            """
            SELECT password_reset_tokens.*, users.username
            FROM password_reset_tokens
            JOIN users ON users.id = password_reset_tokens.user_id
            WHERE password_reset_tokens.token_hash = ? AND password_reset_tokens.used_at IS NULL
            """,
            (hash_reset_token(token),),
        )
        if reset is None or parse_timestamp(reset["expires_at"]) < datetime.utcnow():
            return None
        return reset

    def sla_status_for_ticket(ticket, now=None):
        target_hours = SLA_TARGET_HOURS.get(ticket["priority"], SLA_TARGET_HOURS["medium"])
        created_at = parse_timestamp(ticket["created_at"])
        deadline = created_at + timedelta(hours=target_hours)
        now = now or datetime.utcnow()

        if ticket["status"] == "closed":
            resolved_at = parse_timestamp(ticket["updated_at"])
            return {
                "status": "resolved",
                "label": "Resolved within SLA" if resolved_at <= deadline else "Resolved after SLA",
                "deadline": deadline.strftime("%Y-%m-%d %H:%M"),
                "remaining": "Closed",
                "target_hours": target_hours,
            }

        remaining = deadline - now
        elapsed = now - created_at
        at_risk_after = timedelta(hours=target_hours * 0.75)

        if remaining.total_seconds() <= 0:
            overdue = now - deadline
            status = "breached"
            label = "SLA breached"
            remaining_text = f"Overdue by {format_duration(overdue)}"
        elif elapsed >= at_risk_after:
            status = "at_risk"
            label = "SLA at risk"
            remaining_text = f"Due in {format_duration(remaining)}"
        else:
            status = "on_track"
            label = "SLA on track"
            remaining_text = f"Due in {format_duration(remaining)}"

        return {
            "status": status,
            "label": label,
            "deadline": deadline.strftime("%Y-%m-%d %H:%M"),
            "remaining": remaining_text,
            "target_hours": target_hours,
        }

    def format_duration(delta):
        total_minutes = max(1, int(delta.total_seconds() // 60))
        days, remainder = divmod(total_minutes, 60 * 24)
        hours, minutes = divmod(remainder, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if not parts and minutes:
            parts.append(f"{minutes}m")
        return " ".join(parts[:2]) or "less than 1m"

    def with_sla(ticket):
        enriched = dict(ticket)
        enriched["sla"] = sla_status_for_ticket(enriched)
        return enriched

    def sla_counts_for_tickets(tickets):
        counts = {"on_track": 0, "at_risk": 0, "breached": 0}
        for ticket in tickets:
            status = ticket["sla"]["status"]
            if status in counts:
                counts[status] += 1
        return counts

    ERROR_MESSAGES = {
        400: (
            "We could not process that request.",
            "Refresh the page and try again. If you were submitting a form, your security token may have expired.",
        ),
        403: (
            "You do not have access to that page.",
            "Sign in with an account that has permission, or return to your dashboard.",
        ),
        404: (
            "We could not find that page.",
            "The ticket, file, or page may have been moved or deleted.",
        ),
        413: (
            "That file is too large.",
            f"Attachments must be {MAX_FILE_BYTES // 1024 // 1024} MB or smaller.",
        ),
        429: (
            "Too many requests.",
            "Wait a moment, then try again.",
        ),
        500: (
            "Something went wrong on our side.",
            "The request could not be completed. Try again, or contact support if it keeps happening.",
        ),
    }

    def render_error(error, status_code=None):
        code = status_code or getattr(error, "code", 500)
        title, message = ERROR_MESSAGES.get(code, ERROR_MESSAGES[500])
        detail = getattr(error, "description", "")
        if detail == getattr(error, "name", ""):
            detail = ""
        return render_template(
            "error.html",
            code=code,
            title=title,
            message=message,
            detail=detail,
        ), code

    def send_notification(subject, recipients, body):
        """Send an email. No-ops if MAIL_DEFAULT_SENDER is not configured."""
        filtered = [r for r in recipients if r]
        if not app.config.get("MAIL_DEFAULT_SENDER") or not filtered:
            return
        
        def _send():
            with app.app_context():
                try:
                    msg = Message(subject, recipients=filtered, body=body)
                    test_outbox = app.config.get("MAIL_TEST_OUTBOX")
                    if test_outbox is not None:
                        test_outbox.append(msg)
                        return
                    mail.send(msg)
                except Exception:
                    pass

        if app.config.get("TESTING"):
            _send()
            return

        threading.Thread(target=_send, daemon=True).start()

    def create_notification(user_id, ticket_id, notification_type, message):
        """Create an in-app notification for a user."""
        execute(
            "INSERT INTO notifications (user_id, ticket_id, type, message) VALUES (?, ?, ?, ?)",
            (user_id, ticket_id, notification_type, message)
        )

    def notify_user(user_id, ticket_id, notification_type, message, email_subject=None, email_body=None, email_pref_field=None):
        """Send both in-app notification and email (if preferences allow)."""
        # Create in-app notification
        create_notification(user_id, ticket_id, notification_type, message)
        
        # Send email if user has preference enabled
        if email_subject and email_body and email_pref_field:
            user = query_one(f"SELECT email, {email_pref_field} FROM users WHERE id = ?", (user_id,))
            if user and user["email"] and user[email_pref_field]:
                send_notification(email_subject, [user["email"]], email_body)
        
    def generate_ticket_summary(ticket, comments):
        if not OPENAI_AVAILABLE or not os.getenv("OPENAI_API_KEY"):
            return "OpenAI API key is not configured."

        conversation = []

        for comment in comments:
            conversation.append(
                f'{comment["username"]}: {comment["body"]}'
            )

        prompt = f"""
You are an IT helpdesk assistant.

Summarize this support ticket in 4-8 concise bullet points.

Include:
- Customer problem
- Important troubleshooting already performed
- Current status
- Outstanding issues
- Recommended next step

Ticket

Title:
{ticket["title"]}

Category:
{ticket["category"]}

Priority:
{ticket["priority"]}

Status:
{ticket["status"]}

Description:
{ticket["description"]}

Comments:

{chr(10).join(conversation)}
"""

        try:
            response = client.responses.create(
                model="gpt-4.1-mini",
                input=prompt,
            )

            return response.output_text

        except Exception as e:
            return f"Unable to generate summary: {e}"

    def log_action(ticket_id, action, detail=""):
        execute(
            "INSERT INTO audit_log (ticket_id, user_id, action, detail) VALUES (?, ?, ?, ?)",
            (ticket_id, g.user["id"], action, detail),
        )

    def load_logged_in_user():
        user_id = session.get("user_id")
        g.user = query_one("SELECT * FROM users WHERE id = ?", (user_id,)) if user_id else None

    def login_required(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    def admin_required(view):
        @wraps(view)
        @login_required
        def wrapped_view(**kwargs):
            if g.user["role"] != "admin":
                abort(403)
            return view(**kwargs)

        return wrapped_view

    def get_ticket(ticket_id):
        ticket = query_one(
            """
            SELECT tickets.*, owner.username AS owner_username, assignee.username AS assignee_username
            FROM tickets
            JOIN users AS owner ON owner.id = tickets.user_id
            LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
            WHERE tickets.id = ?
            """,
            (ticket_id,),
        )
        if ticket is None:
            abort(404)
        if g.user["role"] != "admin" and ticket["user_id"] != g.user["id"]:
            abort(403)
        return with_sla(ticket)

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return render_error(error)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        if app.config.get("TESTING"):
            raise error
        app.logger.exception("Unhandled application error")
        return render_error(error, 500)

    init_db()
    

    @app.before_request
    def before_request():
        load_logged_in_user()
        if request.method == "GET":
            new_csrf_token()
        # Load unread notification count for logged-in users
        if g.user:
            g.unread_notifications = query_one(
                "SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0",
                (g.user["id"],)
            )["count"]
        else:
            g.unread_notifications = 0

    @app.teardown_appcontext
    def teardown_db(error):
        close_db(error)

    @app.context_processor
    def inject_helpers():
        from datetime import date
        return {"csrf_token": new_csrf_token(), "today": date.today().isoformat()}

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=("GET", "POST"))
    @limiter.limit("5 per minute;20 per hour", methods=["POST"])
    def register():
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()
            if not username or not password:
                flash("Username and password are required.", "error")
            elif not USERNAME_PATTERN.fullmatch(username):
                flash("Username must be 3-50 characters and use only letters, numbers, dots, dashes, or underscores.", "error")
            elif query_one("SELECT id FROM users WHERE username = ?", (username,)):
                flash("Username already exists.", "error")
            else:
                has_admin = query_one("SELECT id FROM users WHERE role = 'admin'")
                role = "user" if has_admin else "admin"
                execute(
                    "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                    (username, generate_password_hash(password), role, email),
                )
                rotate_csrf_token()
                flash(f"Account created. You can now log in as {username}.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=("GET", "POST"))
    @limiter.limit("10 per minute;50 per hour", methods=["POST"])
    def login():
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = query_one("SELECT * FROM users WHERE username = ?", (username,))
            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid username or password.", "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                rotate_csrf_token()
                return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/reset-password/<token>", methods=("GET", "POST"))
    @limiter.limit("5 per minute", methods=["POST"])
    def reset_password(token):
        reset = get_valid_password_reset(token)
        if reset is None:
            flash("Password reset link is invalid or expired.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            validate_csrf()
            new_password = request.form.get("new_password", "")
            if not new_password:
                flash("New password is required.", "error")
            else:
                execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), reset["user_id"]),
                )
                execute(
                    "UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (reset["id"],),
                )
                flash("Password updated. You can now log in.", "success")
                return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    @app.route("/logout", methods=("POST",))
    @login_required
    def logout():
        validate_csrf()
        session.clear()
        flash("Logged out successfully.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        status = request.args.get("status", "").strip()
        search = request.args.get("search", "").strip()
        priority = request.args.get("priority", "").strip()
        category = request.args.get("category", "").strip()
        sla = request.args.get("sla", "").strip()
        if priority not in {"low", "medium", "high"}:
            priority = ""
        if sla not in {"on_track", "at_risk", "breached"}:
            sla = ""
        sort = request.args.get("sort", "").strip()
        if sort not in SORT_OPTIONS:
            sort = "updated_desc"
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1

        where_parts = []
        where_params = []

        if g.user["role"] != "admin":
            where_parts.append("tickets.user_id = ?")
            where_params.append(g.user["id"])

        if status:
            where_parts.append("tickets.status = ?")
            where_params.append(status)
        if priority:
            where_parts.append("tickets.priority = ?")
            where_params.append(priority)
        if category:
            where_parts.append("tickets.category = ?")
            where_params.append(category)
        if search:
            where_parts.append(
                "(tickets.title LIKE ? ESCAPE '\\' OR tickets.description LIKE ? ESCAPE '\\' OR tickets.category LIKE ? ESCAPE '\\')"
            )
            wildcard = f"%{escape_like(search)}%"
            where_params.extend([wildcard, wildcard, wildcard])

        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

        data_query = (
            """
            SELECT tickets.*, owner.username AS owner_username, assignee.username AS assignee_username
            FROM tickets
            JOIN users AS owner ON owner.id = tickets.user_id
            LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
            """
            + where_clause
            + f" ORDER BY {SORT_OPTIONS[sort]}"
        )
        filtered_tickets = [with_sla(ticket) for ticket in query_all(data_query, tuple(where_params))]
        if sla:
            filtered_tickets = [ticket for ticket in filtered_tickets if ticket["sla"]["status"] == sla]

        total = len(filtered_tickets)
        total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
        page = min(page, total_pages)
        tickets = filtered_tickets[(page - 1) * PER_PAGE:page * PER_PAGE]

        sla_scope_where = ""
        sla_scope_params = []
        if g.user["role"] != "admin":
            sla_scope_where = " WHERE user_id = ?"
            sla_scope_params.append(g.user["id"])
        sla_scope_tickets = [
            with_sla(ticket)
            for ticket in query_all("SELECT * FROM tickets" + sla_scope_where, tuple(sla_scope_params))
        ]
        sla_counts = sla_counts_for_tickets(sla_scope_tickets)

        if g.user["role"] == "admin":
            stats = {
                "open": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'open'")["count"],
                "in_progress": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'in_progress'")["count"],
                "closed": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'closed'")["count"],
            }
            categories = [r["category"] for r in query_all("SELECT DISTINCT category FROM tickets ORDER BY category")]
            
            # Enhanced statistics
            category_stats = query_all(
                "SELECT category, COUNT(*) as count FROM tickets GROUP BY category ORDER BY count DESC LIMIT 10"
            )
            priority_stats = query_all(
                "SELECT priority, COUNT(*) as count FROM tickets GROUP BY priority ORDER BY CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END"
            )
            # Last 30 days trend
            trend_data = query_all(
                """
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM tickets 
                WHERE created_at >= DATE('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY date
                """
            )
            # Average resolution time (in days) for closed tickets
            avg_resolution = query_one(
                """
                SELECT AVG(JULIANDAY(updated_at) - JULIANDAY(created_at)) as avg_days
                FROM tickets
                WHERE status = 'closed'
                """
            )["avg_days"] or 0
        else:
            stats = {
                "open": query_one(
                    "SELECT COUNT(*) AS count FROM tickets WHERE status = 'open' AND user_id = ?",
                    (g.user["id"],),
                )["count"],
                "in_progress": query_one(
                    "SELECT COUNT(*) AS count FROM tickets WHERE status = 'in_progress' AND user_id = ?",
                    (g.user["id"],),
                )["count"],
                "closed": query_one(
                    "SELECT COUNT(*) AS count FROM tickets WHERE status = 'closed' AND user_id = ?",
                    (g.user["id"],),
                )["count"],
            }
            categories = [r["category"] for r in query_all(
                "SELECT DISTINCT category FROM tickets WHERE user_id = ? ORDER BY category",
                (g.user["id"],),
            )]
            
            # Enhanced statistics for regular users
            category_stats = query_all(
                "SELECT category, COUNT(*) as count FROM tickets WHERE user_id = ? GROUP BY category ORDER BY count DESC LIMIT 10",
                (g.user["id"],)
            )
            priority_stats = query_all(
                "SELECT priority, COUNT(*) as count FROM tickets WHERE user_id = ? GROUP BY priority ORDER BY CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END",
                (g.user["id"],)
            )
            trend_data = query_all(
                """
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM tickets 
                WHERE user_id = ? AND created_at >= DATE('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY date
                """,
                (g.user["id"],)
            )
            avg_resolution = query_one(
                """
                SELECT AVG(JULIANDAY(updated_at) - JULIANDAY(created_at)) as avg_days
                FROM tickets
                WHERE status = 'closed' AND user_id = ?
                """,
                (g.user["id"],)
            )["avg_days"] or 0
            
        admins = query_all("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
        templates = query_all("SELECT * FROM ticket_templates WHERE is_active = 1 ORDER BY name")
        return render_template(
            "dashboard.html",
            tickets=tickets,
            admins=admins,
            templates=templates,
            status=status,
            search=search,
            priority=priority,
            category=category,
            sla=sla,
            categories=categories,
            sort=sort,
            stats=stats,
            sla_counts=sla_counts,
            category_stats=category_stats,
            priority_stats=priority_stats,
            trend_data=trend_data,
            avg_resolution=avg_resolution,
            page=page,
            total_pages=total_pages,
            total=total,
        )

    @app.route("/search")
    @login_required
    def advanced_search():
        # Get search parameters
        keywords = request.args.get("keywords", "").strip()
        status = request.args.get("status", "").strip()
        priority = request.args.get("priority", "").strip()
        category = request.args.get("category", "").strip()
        assigned_to = request.args.get("assigned_to", "").strip()
        created_by = request.args.get("created_by", "").strip()
        created_from = request.args.get("created_from", "").strip()
        created_to = request.args.get("created_to", "").strip()
        updated_from = request.args.get("updated_from", "").strip()
        updated_to = request.args.get("updated_to", "").strip()
        
        # Validate inputs
        if status and status not in {"open", "in_progress", "closed"}:
            status = ""
        if priority and priority not in {"low", "medium", "high"}:
            priority = ""
        
        # Get categories and users for dropdowns
        categories = [r["category"] for r in query_all("SELECT DISTINCT category FROM tickets ORDER BY category")]
        users = query_all("SELECT id, username, role FROM users ORDER BY username")
        
        # Build search query
        where_parts = []
        where_params = []
        
        # Non-admins can only see their own tickets
        if g.user["role"] != "admin":
            where_parts.append("tickets.user_id = ?")
            where_params.append(g.user["id"])
        
        # Keyword search (title, description, category)
        if keywords:
            where_parts.append(
                "(tickets.title LIKE ? ESCAPE '\\' OR tickets.description LIKE ? ESCAPE '\\' OR tickets.category LIKE ? ESCAPE '\\')"
            )
            wildcard = f"%{escape_like(keywords)}%"
            where_params.extend([wildcard, wildcard, wildcard])
        
        # Status filter
        if status:
            where_parts.append("tickets.status = ?")
            where_params.append(status)
        
        # Priority filter
        if priority:
            where_parts.append("tickets.priority = ?")
            where_params.append(priority)
        
        # Category filter
        if category:
            where_parts.append("tickets.category = ?")
            where_params.append(category)
        
        # Assigned to filter
        if assigned_to:
            if assigned_to == "unassigned":
                where_parts.append("tickets.assigned_to IS NULL")
            else:
                try:
                    assigned_to_id = int(assigned_to)
                    where_parts.append("tickets.assigned_to = ?")
                    where_params.append(assigned_to_id)
                except ValueError:
                    pass
        
        # Created by filter
        if created_by:
            try:
                created_by_id = int(created_by)
                where_parts.append("tickets.user_id = ?")
                where_params.append(created_by_id)
            except ValueError:
                pass
        
        # Date range filters
        if created_from:
            where_parts.append("DATE(tickets.created_at) >= DATE(?)")
            where_params.append(created_from)
        if created_to:
            where_parts.append("DATE(tickets.created_at) <= DATE(?)")
            where_params.append(created_to)
        if updated_from:
            where_parts.append("DATE(tickets.updated_at) >= DATE(?)")
            where_params.append(updated_from)
        if updated_to:
            where_parts.append("DATE(tickets.updated_at) <= DATE(?)")
            where_params.append(updated_to)
        
        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        
        # Execute search
        results = []
        total_results = 0
        if where_parts or request.args:  # Only search if filters applied or page visited with params
            total_results = query_one(
                "SELECT COUNT(*) AS count FROM tickets" + where_clause,
                tuple(where_params),
            )["count"]
            
            results = query_all(
                """
                SELECT tickets.*, 
                       owner.username AS owner_username, 
                       assignee.username AS assignee_username
                FROM tickets
                JOIN users AS owner ON owner.id = tickets.user_id
                LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
                """
                + where_clause
                + " ORDER BY tickets.updated_at DESC LIMIT 100",
                tuple(where_params),
            )
        
        return render_template(
            "search.html",
            results=results,
            total_results=total_results,
            keywords=keywords,
            status=status,
            priority=priority,
            category=category,
            assigned_to=assigned_to,
            created_by=created_by,
            created_from=created_from,
            created_to=created_to,
            updated_from=updated_from,
            updated_to=updated_to,
            categories=categories,
            users=users,
        )

    @app.route("/tickets/new", methods=("GET", "POST"))
    @login_required
    def create_ticket():
        template = None
        template_id = request.args.get("template_id", type=int)
        if template_id:
            template = query_one(
                "SELECT * FROM ticket_templates WHERE id = ? AND is_active = 1",
                (template_id,)
            )
        
        if request.method == "POST":
            validate_csrf()
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip()
            priority = request.form.get("priority", "medium")
            due_date = request.form.get("due_date", "").strip() or None
            error = validate_ticket_fields(title, description, category)
            if error:
                flash(error, "error")
            else:
                cursor = execute(
                    """
                    INSERT INTO tickets (title, description, category, priority, user_id, due_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (title, description, category, priority, g.user["id"], due_date),
                )
                new_ticket_id = cursor.lastrowid
                
                # Notify admins of new ticket
                admins = query_all("SELECT id, email, email_on_new_ticket FROM users WHERE role = 'admin'")
                ticket_url = url_for("ticket_detail", ticket_id=new_ticket_id, _external=True)
                for admin in admins:
                    notify_user(
                        admin["id"],
                        new_ticket_id,
                        "new_ticket",
                        f"New ticket submitted by {g.user['username']}: {title}",
                        f"[HelpDesk] New ticket #{new_ticket_id}: {title}",
                        f"A new ticket has been submitted by {g.user['username']}.\n\n"
                        f"Title: {title}\nCategory: {category}\nPriority: {priority}\n\n"
                        f"View ticket: {ticket_url}",
                        "email_on_new_ticket"
                    )
                
                log_action(new_ticket_id, "ticket_created", "Ticket created")
                flash("Ticket created successfully.", "success")
                return redirect(url_for("ticket_detail", ticket_id=new_ticket_id))
        return render_template("ticket_form.html", ticket=None, template=template)

    @app.route("/tickets/<int:ticket_id>")
    @login_required
    def ticket_detail(ticket_id):
        ticket = get_ticket(ticket_id)
        comments = query_all(
            """
            SELECT comments.*, users.username
            FROM comments
            JOIN users ON users.id = comments.user_id
            WHERE ticket_id = ?
            ORDER BY comments.created_at ASC, comments.id ASC
            """,
            (ticket_id,),
        )
        attachments = query_all(
            """
            SELECT attachments.*, users.username AS uploader
            FROM attachments
            JOIN users ON users.id = attachments.user_id
            WHERE attachments.ticket_id = ?
            ORDER BY attachments.created_at ASC, attachments.id ASC
            """,
            (ticket_id,),
        )
        internal_notes = []
        if g.user["role"] == "admin":
            internal_notes = query_all(
                """
                SELECT internal_notes.*, users.username
                FROM internal_notes
                JOIN users ON users.id = internal_notes.user_id
                WHERE internal_notes.ticket_id = ?
                ORDER BY internal_notes.created_at ASC, internal_notes.id ASC
                """,
                (ticket_id,),
            )
        activity = query_all(
            """
            SELECT audit_log.*, users.username AS actor
            FROM audit_log
            JOIN users ON users.id = audit_log.user_id
            WHERE audit_log.ticket_id = ?
            ORDER BY audit_log.created_at ASC, audit_log.id ASC
            """,
            (ticket_id,),
        )
        admins = query_all("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
        return render_template(
            "ticket_detail.html",
            ticket=ticket,
            comments=comments,
            attachments=attachments,
            internal_notes=internal_notes,
            activity=activity,
            admins=admins,
        )
        
    @app.route("/tickets/<int:ticket_id>/summary")
    @login_required
    @limiter.limit("2 per minute", methods=["GET"])
    def ticket_summary(ticket_id):

        ticket = get_ticket(ticket_id)

        comments = query_all(
        """
        SELECT comments.*, users.username
        FROM comments
        JOIN users ON users.id = comments.user_id
        WHERE ticket_id = ?
        ORDER BY comments.created_at ASC
        """,
        (ticket_id,),
    )

        summary = generate_ticket_summary(ticket, comments)

        return {
            "summary": summary
    }

    @app.route("/tickets/<int:ticket_id>/edit", methods=("GET", "POST"))
    @login_required
    def edit_ticket(ticket_id):
        ticket = get_ticket(ticket_id)

        if request.method == "POST":
            validate_csrf()
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip()
            priority = request.form.get("priority", "medium")
            due_date = request.form.get("due_date", "").strip() or None
            error = validate_ticket_fields(title, description, category)
            if error:
                flash(error, "error")
            else:
                execute(
                    """
                    UPDATE tickets
                    SET title = ?, description = ?, category = ?, priority = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (title, description, category, priority, due_date, ticket_id),
                )
                flash("Ticket updated successfully.", "success")
                return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        return render_template("ticket_form.html", ticket=ticket)

    @app.route("/tickets/<int:ticket_id>/comment", methods=("POST",))
    @login_required
    def add_comment(ticket_id):
        validate_csrf()
        ticket = get_ticket(ticket_id)
        body = request.form.get("body", "").strip()
        if not body:
            flash("Comment cannot be empty.", "error")
        elif len(body) > MAX_COMMENT_LENGTH:
            flash(f"Comment must be {MAX_COMMENT_LENGTH} characters or fewer.", "error")
        else:
            execute(
                "INSERT INTO comments (ticket_id, user_id, body) VALUES (?, ?, ?)",
                (ticket["id"], g.user["id"], body),
            )
            execute("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
            
            comment_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            email_body = f"{g.user['username']} added a comment on ticket #{ticket_id}: {ticket['title']}\n\n{body}\n\nView ticket: {comment_url}"
            
            # Notify ticket owner if they're not the commenter
            if ticket["user_id"] != g.user["id"]:
                notify_user(
                    ticket["user_id"],
                    ticket_id,
                    "comment_added",
                    f"New comment on ticket #{ticket_id} ({ticket['title']}) by {g.user['username']}",
                    f"[HelpDesk] New comment on ticket #{ticket_id}: {ticket['title']}",
                    email_body,
                    "email_on_comment"
                )
            
            # Notify assignee if they're not the commenter and not the owner
            if (
                ticket["assigned_to"]
                and ticket["assigned_to"] != g.user["id"]
                and ticket["assigned_to"] != ticket["user_id"]
            ):
                notify_user(
                    ticket["assigned_to"],
                    ticket_id,
                    "comment_added",
                    f"New comment on ticket #{ticket_id} ({ticket['title']}) by {g.user['username']}",
                    f"[HelpDesk] New comment on ticket #{ticket_id}: {ticket['title']}",
                    email_body,
                    "email_on_comment"
                )
            
            log_action(ticket_id, "comment_added", "Comment added")
            flash("Comment added.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/internal-notes", methods=("POST",))
    @admin_required
    def add_internal_note(ticket_id):
        validate_csrf()
        ticket = get_ticket(ticket_id)
        body = request.form.get("body", "").strip()
        if not body:
            flash("Internal note cannot be empty.", "error")
        elif len(body) > MAX_COMMENT_LENGTH:
            flash(f"Internal note must be {MAX_COMMENT_LENGTH} characters or fewer.", "error")
        else:
            execute(
                "INSERT INTO internal_notes (ticket_id, user_id, body) VALUES (?, ?, ?)",
                (ticket["id"], g.user["id"], body),
            )
            execute("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", (ticket_id,))
            log_action(ticket_id, "internal_note_added", "Internal note added")
            flash("Internal note added.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/assign", methods=("POST",))
    @admin_required
    def assign_ticket(ticket_id):
        validate_csrf()
        ticket = get_ticket(ticket_id)
        assigned_to = request.form.get("assigned_to", "").strip()
        try:
            assignee_id = int(assigned_to) if assigned_to else None
        except ValueError:
            abort(400)
        if assignee_id is not None:
            assignee = query_one("SELECT id, email, username FROM users WHERE id = ? AND role = 'admin'", (assignee_id,))
            if assignee is None:
                abort(400)
        else:
            assignee = None
        execute(
            "UPDATE tickets SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (assignee_id, ticket_id),
        )
        if assignee:
            log_action(ticket_id, "assigned", f"Assigned to {assignee['username']}")
            # Notify the assignee
            assign_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            notify_user(
                assignee["id"],
                ticket_id,
                "assigned",
                f"Ticket #{ticket_id} ({ticket['title']}) has been assigned to you",
                f"[HelpDesk] Ticket #{ticket_id} assigned to you",
                f"Ticket #{ticket_id}: {ticket['title']} has been assigned to you by {g.user['username']}.\n\n"
                f"View ticket: {assign_url}",
                "email_on_assign"
            )
        else:
            log_action(ticket_id, "assigned", "Assignment cleared")
        flash("Ticket assignment updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/status", methods=("POST",))
    @admin_required
    def update_ticket_status(ticket_id):
        validate_csrf()
        ticket = get_ticket(ticket_id)
        status = request.form.get("status", "open")
        resolution_notes = request.form.get("resolution_notes", "").strip()
        if status not in {"open", "in_progress", "closed"}:
            abort(400)
        execute(
            """
            UPDATE tickets
            SET status = ?, resolution_notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, resolution_notes, ticket_id),
        )
        if ticket["status"] != status:
            log_action(ticket_id, "status_changed", f"Status changed from {ticket['status']} to {status}")
            # Notify ticket owner of status change
            status_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            notify_user(
                ticket["user_id"],
                ticket_id,
                "status_changed",
                f"Ticket #{ticket_id} ({ticket['title']}) status changed to {status}",
                f"[HelpDesk] Ticket #{ticket_id} status updated: {status}",
                f"Your ticket #{ticket_id}: {ticket['title']} has been updated.\n\n"
                f"New status: {status}\n"
                + (f"Resolution notes: {resolution_notes}\n" if resolution_notes else "")
                + f"\nView ticket: {status_url}",
                "email_on_status"
            )
        flash("Ticket status updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/delete", methods=("POST",))
    @admin_required
    def delete_ticket(ticket_id):
        validate_csrf()
        get_ticket(ticket_id)
        for att in query_all("SELECT filename FROM attachments WHERE ticket_id = ?", (ticket_id,)):
            file_path = os.path.join(app.instance_path, "uploads", att["filename"])
            if os.path.isfile(file_path):
                os.remove(file_path)
        execute("DELETE FROM audit_log WHERE ticket_id = ?", (ticket_id,))
        execute("DELETE FROM attachments WHERE ticket_id = ?", (ticket_id,))
        execute("DELETE FROM comments WHERE ticket_id = ?", (ticket_id,))
        execute("DELETE FROM internal_notes WHERE ticket_id = ?", (ticket_id,))
        execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
        flash("Ticket deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/tickets/<int:ticket_id>/attachments", methods=("POST",))
    @login_required
    def upload_attachment(ticket_id):
        validate_csrf()
        get_ticket(ticket_id)
        files = request.files.getlist("file")
        if not files or all(not f.filename for f in files):
            flash("No file selected.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        
        upload_dir = os.path.join(app.instance_path, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        
        uploaded_count = 0
        errors = []
        
        for file in files:
            if not file.filename:
                continue
                
            ext = os.path.splitext(secure_filename(file.filename))[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                errors.append(f"{file.filename}: invalid file type")
                continue
            if uploaded_file_size(file) > MAX_FILE_BYTES:
                file.close()
                abort(413)
            
            try:
                stored_name = f"{uuid.uuid4().hex}{ext}"
                file_path = os.path.join(upload_dir, stored_name)
                file.save(file_path)
                file_size = os.path.getsize(file_path)
                
                execute(
                    "INSERT INTO attachments (ticket_id, user_id, filename, original_name, size) VALUES (?, ?, ?, ?, ?)",
                    (ticket_id, g.user["id"], stored_name, secure_filename(file.filename), file_size),
                )
                uploaded_count += 1
            except Exception as e:
                errors.append(f"{file.filename}: {str(e)}")
        
        if uploaded_count > 0:
            log_action(ticket_id, "attachment_uploaded", f"{uploaded_count} file(s) uploaded")
            flash(f"{uploaded_count} file(s) uploaded successfully.", "success")
        
        if errors:
            for error in errors[:3]:  # Show max 3 errors
                flash(error, "error")
        
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/attachments/<int:attachment_id>")
    @login_required
    def download_attachment(ticket_id, attachment_id):
        get_ticket(ticket_id)
        attachment = query_one(
            "SELECT * FROM attachments WHERE id = ? AND ticket_id = ?",
            (attachment_id, ticket_id),
        )
        if attachment is None:
            abort(404)
        file_path = os.path.join(app.instance_path, "uploads", attachment["filename"])
        if not os.path.isfile(file_path):
            abort(404)
        return send_file(file_path, download_name=attachment["original_name"], as_attachment=False)

    @app.route("/tickets/<int:ticket_id>/attachments/<int:attachment_id>/delete", methods=("POST",))
    @login_required
    def delete_attachment(ticket_id, attachment_id):
        validate_csrf()
        ticket = get_ticket(ticket_id)
        attachment = query_one(
            "SELECT * FROM attachments WHERE id = ? AND ticket_id = ?",
            (attachment_id, ticket_id),
        )
        if attachment is None:
            abort(404)
        if g.user["role"] != "admin" and ticket["user_id"] != g.user["id"]:
            abort(403)
        file_path = os.path.join(app.instance_path, "uploads", attachment["filename"])
        if os.path.isfile(file_path):
            os.remove(file_path)
        execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
        log_action(ticket_id, "attachment_deleted", f"File deleted: {attachment['original_name']}")
        flash("Attachment deleted.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        users = query_all(
            """
            SELECT users.id, users.username, users.role, users.email, users.created_at,
                COUNT(tickets.id) AS ticket_count
            FROM users
            LEFT JOIN tickets ON tickets.user_id = users.id
            GROUP BY users.id
            ORDER BY users.created_at ASC, users.id ASC
            """
        )
        return render_template("admin_users.html", users=users)

    @app.route("/admin/users/<int:user_id>/role", methods=("POST",))
    @admin_required
    def admin_toggle_role(user_id):
        validate_csrf()
        if user_id == g.user["id"]:
            flash("You cannot change your own role.", "error")
            return redirect(url_for("admin_users"))
        user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            abort(404)
        if user["role"] == "admin":
            admin_count = query_one("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")["count"]
            if admin_count <= 1:
                flash("Cannot demote the last admin.", "error")
                return redirect(url_for("admin_users"))
            new_role = "user"
        else:
            new_role = "admin"
        execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        flash(f"{user['username']} is now {new_role}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/password", methods=("POST",))
    @admin_required
    def admin_reset_password(user_id):
        validate_csrf()
        if user_id == g.user["id"]:
            flash("Use your profile page to change your own password.", "error")
            return redirect(url_for("admin_users"))
        user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            abort(404)
        if not user["email"]:
            flash(f"Add an email address for {user['username']} before sending a password reset link.", "error")
            return redirect(url_for("admin_users"))
        if not app.config.get("MAIL_DEFAULT_SENDER"):
            flash("Password reset email is not configured.", "error")
            return redirect(url_for("admin_users"))

        token = create_password_reset_token(user_id)
        reset_url = url_for("reset_password", token=token, _external=True)
        send_notification(
            "[HelpDesk] Password reset link",
            [user["email"]],
            f"A password reset was requested for your HelpDesk account.\n\n"
            f"Reset your password: {reset_url}\n\n"
            "This link expires in 1 hour and can only be used once.",
        )
        flash(f"Password reset link sent to {user['username']}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/delete", methods=("POST",))
    @admin_required
    def admin_delete_user(user_id):
        validate_csrf()
        if user_id == g.user["id"]:
            flash("You cannot delete your own account.", "error")
            return redirect(url_for("admin_users"))
        user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None:
            abort(404)
        if user["role"] == "admin":
            admin_count = query_one("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")["count"]
            if admin_count <= 1:
                flash("Cannot delete the last admin.", "error")
                return redirect(url_for("admin_users"))
        ticket_count = query_one("SELECT COUNT(*) AS count FROM tickets WHERE user_id = ?", (user_id,))["count"]
        if ticket_count > 0:
            flash(
                f"Cannot delete {user['username']} — they have {ticket_count} ticket(s). Delete or reassign them first.",
                "error",
            )
            return redirect(url_for("admin_users"))
        execute("UPDATE tickets SET assigned_to = NULL WHERE assigned_to = ?", (user_id,))
        execute("DELETE FROM users WHERE id = ?", (user_id,))
        flash(f"User {user['username']} deleted.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/templates")
    @admin_required
    def admin_templates():
        templates = query_all(
            """
            SELECT t.*, u.username AS creator
            FROM ticket_templates t
            JOIN users u ON t.created_by = u.id
            ORDER BY t.is_active DESC, t.name ASC
            """
        )
        return render_template("admin_templates.html", templates=templates)

    @app.route("/admin/templates/new", methods=("GET", "POST"))
    @admin_required
    def create_template():
        if request.method == "POST":
            validate_csrf()
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip()
            priority = request.form.get("priority", "medium")
            default_title = request.form.get("default_title", "").strip()
            default_description = request.form.get("default_description", "").strip()
            
            if not name or len(name) > 100:
                flash("Template name is required (max 100 characters).", "error")
            elif not category:
                flash("Category is required.", "error")
            elif not default_title or len(default_title) > 200:
                flash("Default title is required (max 200 characters).", "error")
            elif not default_description:
                flash("Default description is required.", "error")
            else:
                execute(
                    """
                    INSERT INTO ticket_templates 
                    (name, description, category, priority, default_title, default_description, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, description, category, priority, default_title, default_description, g.user["id"]),
                )
                flash("Template created successfully.", "success")
                return redirect(url_for("admin_templates"))
        
        return render_template("template_form.html", template=None)

    @app.route("/admin/templates/<int:template_id>/edit", methods=("GET", "POST"))
    @admin_required
    def edit_template(template_id):
        template = query_one("SELECT * FROM ticket_templates WHERE id = ?", (template_id,))
        if template is None:
            abort(404)
        
        if request.method == "POST":
            validate_csrf()
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            category = request.form.get("category", "").strip()
            priority = request.form.get("priority", "medium")
            default_title = request.form.get("default_title", "").strip()
            default_description = request.form.get("default_description", "").strip()
            
            if not name or len(name) > 100:
                flash("Template name is required (max 100 characters).", "error")
            elif not category:
                flash("Category is required.", "error")
            elif not default_title or len(default_title) > 200:
                flash("Default title is required (max 200 characters).", "error")
            elif not default_description:
                flash("Default description is required.", "error")
            else:
                execute(
                    """
                    UPDATE ticket_templates 
                    SET name = ?, description = ?, category = ?, priority = ?, 
                        default_title = ?, default_description = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (name, description, category, priority, default_title, default_description, template_id),
                )
                flash("Template updated successfully.", "success")
                return redirect(url_for("admin_templates"))
        
        return render_template("template_form.html", template=template)

    @app.route("/admin/templates/<int:template_id>/toggle", methods=("POST",))
    @admin_required
    def toggle_template(template_id):
        validate_csrf()
        template = query_one("SELECT * FROM ticket_templates WHERE id = ?", (template_id,))
        if template is None:
            abort(404)
        new_status = 0 if template["is_active"] else 1
        execute("UPDATE ticket_templates SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, template_id))
        status_text = "activated" if new_status else "deactivated"
        flash(f"Template {status_text}.", "success")
        return redirect(url_for("admin_templates"))

    @app.route("/admin/templates/<int:template_id>/delete", methods=("POST",))
    @admin_required
    def delete_template(template_id):
        validate_csrf()
        template = query_one("SELECT * FROM ticket_templates WHERE id = ?", (template_id,))
        if template is None:
            abort(404)
        execute("DELETE FROM ticket_templates WHERE id = ?", (template_id,))
        flash("Template deleted.", "success")
        return redirect(url_for("admin_templates"))

    @app.route("/admin/export/tickets.csv")
    @admin_required
    def export_tickets_csv():
        rows = query_all(
            """
            SELECT tickets.id, tickets.title, tickets.category, tickets.priority, tickets.status,
                owner.username AS owner,
                COALESCE(assignee.username, '') AS assigned_to,
                tickets.created_at, tickets.updated_at, tickets.due_date,
                tickets.resolution_notes,
                COUNT(comments.id) AS comment_count
            FROM tickets
            JOIN users AS owner ON owner.id = tickets.user_id
            LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
            LEFT JOIN comments ON comments.ticket_id = tickets.id
            GROUP BY tickets.id
            ORDER BY tickets.id ASC
            """
        )
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "title", "category", "priority", "status", "owner",
                         "assigned_to", "created_at", "updated_at", "due_date", "comment_count", "resolution_notes"])
        for row in rows:
            writer.writerow([
                row["id"], row["title"], row["category"], row["priority"], row["status"],
                row["owner"], row["assigned_to"], row["created_at"], row["updated_at"],
                row["due_date"] or "", row["comment_count"], row["resolution_notes"],
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=tickets.csv"},
        )

    @app.errorhandler(413)
    def file_too_large(e):
        return render_error(e, 413)

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    @app.route("/profile/email", methods=("POST",))
    @login_required
    def update_email():
        validate_csrf()
        email = request.form.get("email", "").strip()
        execute("UPDATE users SET email = ? WHERE id = ?", (email, g.user["id"]))
        flash("Email updated.", "success")
        return redirect(url_for("profile"))

    @app.route("/profile/password", methods=("POST",))
    @login_required
    def change_password():
        validate_csrf()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        if not current_password or not new_password:
            flash("Both fields are required.", "error")
        elif not check_password_hash(g.user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        else:
            execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_password), g.user["id"]),
            )
            flash("Password updated.", "success")
        return redirect(url_for("profile"))

    @app.route("/profile/notifications", methods=("POST",))
    @login_required
    def update_notification_preferences():
        validate_csrf()
        email_on_assign = 1 if request.form.get("email_on_assign") else 0
        email_on_comment = 1 if request.form.get("email_on_comment") else 0
        email_on_status = 1 if request.form.get("email_on_status") else 0
        email_on_new_ticket = 1 if request.form.get("email_on_new_ticket") else 0
        
        execute(
            """UPDATE users 
               SET email_on_assign = ?, email_on_comment = ?, email_on_status = ?, email_on_new_ticket = ?
               WHERE id = ?""",
            (email_on_assign, email_on_comment, email_on_status, email_on_new_ticket, g.user["id"])
        )
        flash("Notification preferences updated.", "success")
        return redirect(url_for("profile"))

    @app.route("/notifications")
    @login_required
    def notifications():
        page = max(1, int(request.args.get("page", "1")))
        per_page = 20
        offset = (page - 1) * per_page
        
        notifications_list = query_all(
            """SELECT notifications.*, tickets.title as ticket_title
               FROM notifications
               JOIN tickets ON tickets.id = notifications.ticket_id
               WHERE notifications.user_id = ?
               ORDER BY notifications.created_at DESC
               LIMIT ? OFFSET ?""",
            (g.user["id"], per_page, offset)
        )
        
        total = query_one(
            "SELECT COUNT(*) as count FROM notifications WHERE user_id = ?",
            (g.user["id"],)
        )["count"]
        
        total_pages = max(1, (total + per_page - 1) // per_page)
        
        return render_template(
            "notifications.html",
            notifications=notifications_list,
            page=page,
            total_pages=total_pages
        )

    @app.route("/notifications/mark-read/<int:notification_id>", methods=("POST",))
    @login_required
    def mark_notification_read(notification_id):
        validate_csrf()
        execute(
            "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
            (notification_id, g.user["id"])
        )
        return redirect(url_for("notifications"))

    @app.route("/notifications/mark-all-read", methods=("POST",))
    @login_required
    def mark_all_notifications_read():
        validate_csrf()
        execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
            (g.user["id"],)
        )
        flash("All notifications marked as read.", "success")
        return redirect(url_for("notifications"))

    @app.errorhandler(429)
    def ratelimit_exceeded(e):
        return render_error(e, 429)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
