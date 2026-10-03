# Admin panel image.
#
# The bot's Dockerfile builds from the same source tree but only copies the
# packages the bot needs. Here we copy the same shared packages plus the
# admin application, so both services run identical application code
# against the identical database models.

FROM python:3.11-slim

# tini forwards SIGTERM so uvicorn can shut down cleanly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared packages (identical to the bot image).
COPY main.py ./
COPY config/     ./config/
COPY security/   ./security/
COPY core/       ./core/
COPY parser/     ./parser/
COPY database/   ./database/
COPY workers/    ./workers/

# Admin application.
COPY admin/      ./admin/

# Non-root: the panel needs no write access to its own code.
RUN useradd --create-home --uid 10002 netsentinel \
    && chown -R netsentinel:netsentinel /app
USER netsentinel

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ADMIN_HOST=0.0.0.0 \
    ADMIN_PORT=8080

ENTRYPOINT ["/usr/bin/tini", "--"]
# Module mode: `python -m admin.main` puts /app (not /app/admin) on
# sys.path, so `import admin.services...` resolves.
CMD ["python", "-m", "admin.main"]