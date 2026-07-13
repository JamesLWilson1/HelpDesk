import csv
import io
import os
import re
import secrets
import sqlite3
import threading
import uuid
from functools import wraps
from openai import OpenAI

from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
MAX_TITLE_LENGTH = 120
MAX_CATEGORY_LENGTH = 60
MAX_DESCRIPTION_LENGTH = 2000
MAX_COMMENT_LENGTH = 1000
PER_PAGE = 20
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".csv", ".gif", ".jpeg", ".jpg", ".log", ".pdf", ".png", ".txt", ".webp"}
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

    def send_notification(subject, recipients, body):
        """Send an email in a background thread. No-ops if MAIL_DEFAULT_SENDER is not configured."""
        filtered = [r for r in recipients if r]
        if not app.config.get("MAIL_DEFAULT_SENDER") or not filtered:
            return
        
        def _send():
            with app.app_context():
                try:
                    msg = Message(subject, recipients=filtered, body=body)
                    mail.send(msg)
                except Exception:
                    pass

        threading.Thread(target=_send, daemon=True).start()
        
    def generate_ticket_summary(ticket, comments):
        if not os.getenv("OPENAI_API_KEY"):
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
        return ticket

    init_db()
    

    @app.before_request
    def before_request():
        load_logged_in_user()
        if request.method == "GET":
            new_csrf_token()

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
        if priority not in {"low", "medium", "high"}:
            priority = ""
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

        total = query_one(
            "SELECT COUNT(*) AS count FROM tickets" + where_clause,
            tuple(where_params),
        )["count"]

        total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
        page = min(page, total_pages)

        data_query = (
            """
            SELECT tickets.*, owner.username AS owner_username, assignee.username AS assignee_username
            FROM tickets
            JOIN users AS owner ON owner.id = tickets.user_id
            LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
            """
            + where_clause
            + f" ORDER BY {SORT_OPTIONS[sort]} LIMIT ? OFFSET ?"
        )
        tickets = query_all(data_query, tuple(where_params) + (PER_PAGE, (page - 1) * PER_PAGE))

        if g.user["role"] == "admin":
            stats = {
                "open": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'open'")["count"],
                "in_progress": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'in_progress'")["count"],
                "closed": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'closed'")["count"],
            }
            categories = [r["category"] for r in query_all("SELECT DISTINCT category FROM tickets ORDER BY category")]
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
        admins = query_all("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
        return render_template(
            "dashboard.html",
            tickets=tickets,
            admins=admins,
            status=status,
            search=search,
            priority=priority,
            category=category,
            categories=categories,
            sort=sort,
            stats=stats,
            page=page,
            total_pages=total_pages,
            total=total,
        )

    @app.route("/tickets/new", methods=("GET", "POST"))
    @login_required
    def create_ticket():
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
                admin_emails = [
                    row["email"] for row in
                    query_all("SELECT email FROM users WHERE role = 'admin' AND email != ''")
                ]
                ticket_url = url_for("ticket_detail", ticket_id=new_ticket_id, _external=True)
                send_notification(
                    f"[HelpDesk] New ticket #{new_ticket_id}: {title}",
                    admin_emails,
                    f"A new ticket has been submitted by {g.user['username']}.\n\n"
                    f"Title: {title}\nCategory: {category}\nPriority: {priority}\n\n"
                    f"View ticket: {ticket_url}",
                )
                log_action(new_ticket_id, "ticket_created", "Ticket created")
                flash("Ticket created successfully.", "success")
                return redirect(url_for("ticket_detail", ticket_id=new_ticket_id))
        return render_template("ticket_form.html", ticket=None)

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
            activity=activity,
            admins=admins,
        )
        
    @app.route("/tickets/<int:ticket_id>/summary")
    @login_required
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
            comment_recipients = []
            if ticket["user_id"] != g.user["id"]:
                owner = query_one("SELECT email FROM users WHERE id = ?", (ticket["user_id"],))
                if owner and owner["email"]:
                    comment_recipients.append(owner["email"])
            if (
                ticket["assigned_to"]
                and ticket["assigned_to"] != g.user["id"]
                and ticket["assigned_to"] != ticket["user_id"]
            ):
                assignee = query_one("SELECT email FROM users WHERE id = ?", (ticket["assigned_to"],))
                if assignee and assignee["email"]:
                    comment_recipients.append(assignee["email"])
            comment_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            send_notification(
                f"[HelpDesk] New comment on ticket #{ticket_id}: {ticket['title']}",
                comment_recipients,
                f"{g.user['username']} added a comment on ticket #{ticket_id}: {ticket['title']}\n\n"
                f"{body}\n\nView ticket: {comment_url}",
            )
            log_action(ticket_id, "comment_added", "Comment added")
            flash("Comment added.", "success")
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
        else:
            log_action(ticket_id, "assigned", "Assignment cleared")
        if assignee and assignee["email"]:
            assign_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            send_notification(
                f"[HelpDesk] Ticket #{ticket_id} assigned to you",
                [assignee["email"]],
                f"Ticket #{ticket_id}: {ticket['title']} has been assigned to you by {g.user['username']}.\n\n"
                f"View ticket: {assign_url}",
            )
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
        owner = query_one("SELECT email FROM users WHERE id = ?", (ticket["user_id"],))
        if owner and owner["email"]:
            status_url = url_for("ticket_detail", ticket_id=ticket_id, _external=True)
            send_notification(
                f"[HelpDesk] Ticket #{ticket_id} status updated: {status}",
                [owner["email"]],
                f"Your ticket #{ticket_id}: {ticket['title']} has been updated.\n\n"
                f"New status: {status}\n"
                + (f"Resolution notes: {resolution_notes}\n" if resolution_notes else "")
                + f"\nView ticket: {status_url}",
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
        execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
        flash("Ticket deleted.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/tickets/<int:ticket_id>/attachments", methods=("POST",))
    @login_required
    def upload_attachment(ticket_id):
        validate_csrf()
        get_ticket(ticket_id)
        file = request.files.get("file")
        if not file or not file.filename:
            flash("No file selected.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        ext = os.path.splitext(secure_filename(file.filename))[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            flash(f"File type not allowed. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        upload_dir = os.path.join(app.instance_path, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        stored_name = f"{uuid.uuid4().hex}{ext}"
        file.save(os.path.join(upload_dir, stored_name))
        file_size = os.path.getsize(os.path.join(upload_dir, stored_name))
        execute(
            "INSERT INTO attachments (ticket_id, user_id, filename, original_name, size) VALUES (?, ?, ?, ?, ?)",
            (ticket_id, g.user["id"], stored_name, secure_filename(file.filename), file_size),
        )
        log_action(ticket_id, "attachment_uploaded", f"File uploaded: {secure_filename(file.filename)}")
        flash("Attachment uploaded.", "success")
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
        new_password = secrets.token_urlsafe(12)
        execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        flash(f"Password for {user['username']} reset to: {new_password}", "success")
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
        flash("File too large. Maximum size is 5 MB.", "error")
        return redirect(request.referrer or url_for("dashboard"))

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

    @app.errorhandler(429)
    def ratelimit_exceeded(e):
        flash("Too many attempts. Please wait a moment and try again.", "error")
        return redirect(request.referrer or url_for("login"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
