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

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake external tools into the image so container startup does not depend on
# GitHub availability or a moving upstream branch. theHarvester 4.11.1 is the
# last verified release for this image's Python 3.13 runtime.
ARG SUBFINDER_VERSION=2.6.7
ARG THEHARVESTER_COMMIT=fd832dee7936458a4f6e2029bf37ba6797228676
RUN curl -fsSL --connect-timeout 15 --max-time 120 \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
        -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm -f /tmp/subfinder.zip \
    && python -m venv /opt/theharvester \
    && /opt/theharvester/bin/pip install --no-cache-dir \
        "git+https://github.com/laramies/theHarvester.git@${THEHARVESTER_COMMIT}" \
    && ln -s /opt/theharvester/bin/theHarvester /usr/local/bin/theHarvester

# Runtime entrypoint starts local services and writes tool configuration.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
