# syntax=docker/dockerfile:1
# Admin panel: React SPA + FastAPI API in one image.
#
# Stage 1 builds the SPA with Node; stage 2 is the Python runtime, so Node
# is a build-time dependency only and never ships in the final image.

FROM node:20-alpine AS frontend
WORKDIR /app/admin/frontend

# Manifests first, so `npm ci` is only re-run when dependencies change.
COPY admin/frontend/package.json admin/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY admin/frontend/ ./
# `tsc -b` runs in the npm build script, so a type error fails the image
# build instead of shipping a broken panel. The test -f guards against a
# silently empty outDir.
RUN npm run build && test -f dist/index.html


FROM python:3.11-slim

# tini reaps zombies and forwards SIGTERM so uvicorn shuts down cleanly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Shared packages, byte-identical to the bot image.
COPY main.py         ./
COPY config/         ./config/
COPY security/       ./security/
COPY core/           ./core/
COPY parser/         ./parser/
COPY database/       ./database/
COPY workers/        ./workers/

# Admin Python sources. dist/ is excluded by .dockerignore and comes from
# the frontend stage below, so a stale local build cannot shadow it; the
# rm is belt-and-braces in case that ignore rule is ever relaxed.
COPY admin/          ./admin/
RUN rm -rf /app/admin/frontend/dist

COPY --from=frontend /app/admin/frontend/dist /app/admin/frontend/dist

# The Jinja2 panel is gone; fail the build if it creeps back in.
RUN rm -f /app/admin/templates.py \
    && rm -rf /app/admin/templates /app/admin/static /app/admin/routes/pages.py

# Non-root: the panel needs no write access to its own code.
RUN useradd --create-home --uid 10002 netsentinel \
    && chown -R netsentinel:netsentinel /app
USER netsentinel

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ADMIN_HOST=0.0.0.0 \
    ADMIN_PORT=8080

ENTRYPOINT ["/usr/bin/tini", "--"]
# Module mode: `python -m admin.main` puts /app on sys.path, so
# `import admin.services...` resolves. Running admin/main.py directly
# would not.
CMD ["python", "-m", "admin.main"]
