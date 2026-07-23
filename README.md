# HelpDesk

HelpDesk is a small Flask + SQLite ticketing system with authentication, role-based access, comments, ticket assignment, status tracking, and a simple dashboard.

## Features

- Login / logout with hashed passwords
- Two roles:
  - **Admin**: can view all tickets, filter/search tickets, assign tickets, change status, and add resolution notes
  - **User**: can create tickets, view their own tickets, edit their own tickets, and comment on them
- SQLite database with users, tickets, comments, notifications, templates, attachments, audit logs, and password reset tokens
- Ticket fields for title, description, category, priority, status, assignment, and resolution notes
- Dashboard with ticket statistics
- Search and status filters
- Simple web UI

## Getting started

1. Create a virtual environment if you want one.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill in any local settings you need.

4. Run the app:

   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:5000`.

## First account bootstrap

The first registered account becomes an **admin** automatically so the system can be bootstrapped without manually seeding a database.

All later registrations become normal **users**.

## Configuration

Set these environment variables for production deployments:

- `SECRET_KEY`: required stable secret for session signing.
- `APP_ENV=production`: enables secure production defaults, including secure session cookies.
- `SESSION_COOKIE_SECURE`: optional explicit override for secure session cookies. Defaults to `true` when `APP_ENV` or `FLASK_ENV` is `production`; defaults to `false` for local development.
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`: required for email notifications and admin-triggered password reset links.

Password reset links are one-time use, expire after 1 hour, and require the target user to have an email address.

Use `.env.example` as the starting template for local and deployment configuration. Do not commit your real `.env` file.

## Deployment checklist

Before deploying, confirm these production settings are in place:

- Set a long, stable `SECRET_KEY`. If this changes between restarts, existing login sessions and CSRF tokens become invalid.
- Set `APP_ENV=production` so secure cookie defaults are enabled.
- Keep `SESSION_COOKIE_SECURE=true` when the site is served over HTTPS. Only override it for local HTTP testing.
- Configure SMTP with `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, and `MAIL_DEFAULT_SENDER`. Password reset links and email notifications depend on working mail delivery.
- Keep `.env` out of version control. Use `.env.example` as the safe template.
- Persist and back up the `instance/` directory. The default SQLite database is `instance/helpdesk.sqlite`, and uploaded ticket files are stored under `instance/uploads/`.
- Put the app behind HTTPS in production. A reverse proxy such as Nginx, Caddy, or a platform-managed load balancer can terminate TLS before forwarding traffic to Gunicorn.
- Run database backups before deploying schema changes. The app applies lightweight SQLite column migrations at startup, but backups are still the rollback plan.

## Docker deployment

Build the image:

```bash
docker build -t helpdesk .
```

Run it with a persisted instance volume and production environment file:

```bash
docker run --rm \
   --name helpdesk \
   --env-file .env \
   -p 8000:8000 \
   -v helpdesk-instance:/app/instance \
   helpdesk
```

Then serve `http://127.0.0.1:8000` behind your production HTTPS proxy.

The Dockerfile intentionally runs Gunicorn with one worker because this project currently uses SQLite and Flask-Limiter's in-memory rate-limit storage. To scale beyond one worker or one container, move the database to Postgres and use a shared rate-limit backend such as Redis.

## Operational notes

- The first registered account becomes the admin account. Register it immediately after first deployment, then create normal users from the app.
- Monitor application logs for SMTP failures, rate-limit warnings, and unexpected 4xx/5xx responses.
- Keep `OPENAI_API_KEY` unset unless AI ticket summaries are needed. If enabled, monitor usage because summary generation calls the OpenAI API.
- Test password reset delivery after configuring SMTP by using the admin user's `Send reset link` action for a user with an email address.
- Periodically verify backups by restoring `instance/helpdesk.sqlite` and `instance/uploads/` into a staging environment.

## Main routes / API behavior

This project is server-rendered HTML, but the main behaviors map cleanly to REST-style resources:

- `GET/POST /register` - create an account
- `GET/POST /login` - authenticate
- `POST /logout` - end session
- `GET /dashboard` - ticket dashboard
- `GET/POST /tickets/new` - create ticket
- `GET /tickets/<id>` - view ticket
- `GET/POST /tickets/<id>/edit` - update ticket
- `POST /tickets/<id>/comment` - add comment
- `POST /tickets/<id>/assign` - admin assigns ticket
- `POST /tickets/<id>/status` - admin updates status and resolution notes

## Running tests

```bash
python -m pytest -q
```
