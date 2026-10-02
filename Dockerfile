FROM python:3.11-slim

# tini reaps zombies and, crucially, forwards SIGTERM to the child so
# python-telegram-bot can shut down cleanly. Without an init process, a
# container stop waits out the full SIGKILL grace period every time.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Explicit package copies — never `COPY . .`, so secrets and junk can never
# reach the image even if .dockerignore is ever edited.
COPY main.py ./
COPY config/     ./config/
COPY security/   ./security/
COPY bot/        ./bot/
COPY core/       ./core/
COPY parser/     ./parser/
COPY database/   ./database/
COPY workers/    ./workers/

# Drop privileges: the bot needs no write access to its own code.
RUN useradd --create-home --uid 10001 netsentinel \
    && chown -R netsentinel:netsentinel /app
USER netsentinel

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# tini as PID 1 (exec form) => SIGTERM reaches python, APScheduler stops,
# in-flight scans are allowed to finish.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "main.py"]