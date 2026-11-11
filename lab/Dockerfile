FROM python:3.13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends snmpd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE requirements.txt snmpcheck.py test_snmpcheck.py ./
RUN pip install --no-cache-dir .
COPY lab/ ./lab/
