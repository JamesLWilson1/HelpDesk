# HelpDesk

HelpDesk is a small Flask + SQLite ticketing system with authentication, role-based access, comments, ticket assignment, status tracking, and a simple dashboard.

## Features

- Login / logout with hashed passwords
- Two roles:
  - **Admin**: can view all tickets, filter/search tickets, assign tickets, change status, and add resolution notes
  - **User**: can create tickets, view their own tickets, edit their own tickets, and comment on them
- SQLite database with `users`, `tickets`, and `comments` tables
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

3. Run the app:

   ```bash
   python app.py
   ```

4. Open `http://127.0.0.1:5000`.

## First account bootstrap

The first registered account becomes an **admin** automatically so the system can be bootstrapped without manually seeding a database.

All later registrations become normal **users**.

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
python -m unittest discover -s tests -v
```
