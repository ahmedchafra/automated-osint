FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Build tools, libpq, curl, unzip, git (for h8mail pip extras), and tor
# (used by the Ahmia collector to optionally proxy .onion traffic).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libpq-dev curl unzip git tor torsocks ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder binary at runtime via entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
