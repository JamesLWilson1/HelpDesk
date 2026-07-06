import os
import re
import secrets
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
MAX_TITLE_LENGTH = 120
MAX_CATEGORY_LENGTH = 60
MAX_DESCRIPTION_LENGTH = 2000
MAX_COMMENT_LENGTH = 1000


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.path.join(app.instance_path, "helpdesk.sqlite"),
    )

    if test_config is not None:
        app.config.update(test_config)

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
            """
        )
        db.commit()
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
        return {"csrf_token": new_csrf_token()}

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=("GET", "POST"))
    def register():
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
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
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), role),
                )
                rotate_csrf_token()
                flash(f"Account created. You can now log in as {username}.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=("GET", "POST"))
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
        filters = []
        params = []

        if g.user["role"] == "admin":
            base_query = (
                """
                SELECT tickets.*, owner.username AS owner_username, assignee.username AS assignee_username
                FROM tickets
                JOIN users AS owner ON owner.id = tickets.user_id
                LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
                """
            )
        else:
            base_query = (
                """
                SELECT tickets.*, owner.username AS owner_username, assignee.username AS assignee_username
                FROM tickets
                JOIN users AS owner ON owner.id = tickets.user_id
                LEFT JOIN users AS assignee ON assignee.id = tickets.assigned_to
                WHERE tickets.user_id = ?
                """
            )
            params.append(g.user["id"])

        if status:
            filters.append("tickets.status = ?")
            params.append(status)
        if search:
            filters.append(
                "(tickets.title LIKE ? ESCAPE '\\' OR tickets.description LIKE ? ESCAPE '\\' OR tickets.category LIKE ? ESCAPE '\\')"
            )
            wildcard = f"%{escape_like(search)}%"
            params.extend([wildcard, wildcard, wildcard])

        if filters:
            joiner = " AND " if "WHERE" in base_query else " WHERE "
            base_query += joiner + " AND ".join(filters)

        base_query += " ORDER BY tickets.updated_at DESC, tickets.id DESC"

        if g.user["role"] == "admin":
            stats = {
                "open": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'open'")["count"],
                "in_progress": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'in_progress'")["count"],
                "closed": query_one("SELECT COUNT(*) AS count FROM tickets WHERE status = 'closed'")["count"],
            }
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
        admins = query_all("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
        tickets = query_all(base_query, tuple(params))
        return render_template(
            "dashboard.html",
            tickets=tickets,
            admins=admins,
            status=status,
            search=search,
            stats=stats,
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
            error = validate_ticket_fields(title, description, category)
            if error:
                flash(error, "error")
            else:
                cursor = execute(
                    """
                    INSERT INTO tickets (title, description, category, priority, user_id)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (title, description, category, priority, g.user["id"]),
                )
                flash("Ticket created successfully.", "success")
                return redirect(url_for("ticket_detail", ticket_id=cursor.lastrowid))
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
        admins = query_all("SELECT id, username FROM users WHERE role = 'admin' ORDER BY username")
        return render_template("ticket_detail.html", ticket=ticket, comments=comments, admins=admins)

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
            error = validate_ticket_fields(title, description, category)
            if error:
                flash(error, "error")
            else:
                execute(
                    """
                    UPDATE tickets
                    SET title = ?, description = ?, category = ?, priority = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (title, description, category, priority, ticket_id),
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
            flash("Comment added.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/assign", methods=("POST",))
    @admin_required
    def assign_ticket(ticket_id):
        validate_csrf()
        get_ticket(ticket_id)
        assigned_to = request.form.get("assigned_to", "").strip()
        try:
            assignee_id = int(assigned_to) if assigned_to else None
        except ValueError:
            abort(400)
        if assignee_id is not None:
            assignee = query_one("SELECT id FROM users WHERE id = ? AND role = 'admin'", (assignee_id,))
            if assignee is None:
                abort(400)
        execute(
            "UPDATE tickets SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (assignee_id, ticket_id),
        )
        flash("Ticket assignment updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    @app.route("/tickets/<int:ticket_id>/status", methods=("POST",))
    @admin_required
    def update_ticket_status(ticket_id):
        validate_csrf()
        get_ticket(ticket_id)
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
        flash("Ticket status updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
