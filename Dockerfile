FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create a non-root user and the instance directory for the SQLite database
RUN adduser --disabled-password --gecos "" appuser && \
    mkdir -p instance && \
    chown -R appuser:appuser /app

USER appuser

# Mount a volume at /app/instance to persist the database across container restarts
VOLUME ["/app/instance"]

EXPOSE 8000

# Single worker: SQLite and in-memory rate limiting don't support multiple workers.
# To scale beyond one worker, switch to Postgres and a Redis-backed rate limiter.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--access-logfile", "-", "app:app"]
