FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Explicit package copies — never `COPY . .`, so secrets and junk can never
# reach the image even if .dockerignore is ever edited.
COPY main.py ./
COPY config/    ./config/
COPY security/  ./security/
COPY bot/       ./bot/
COPY core/      ./core/
COPY parser/    ./parser/
COPY database/  ./database/
COPY workers/   ./workers/

CMD ["python", "main.py"]
