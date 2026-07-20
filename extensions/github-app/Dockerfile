FROM python:3.12-slim

# --- install Node 20 on top of python:3.12-slim ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- install LucidCode Python package ---
COPY pyproject.toml README.md /tmp/lucidcode/
COPY lucidcode /tmp/lucidcode/lucidcode
RUN pip install --no-cache-dir /tmp/lucidcode && rm -rf /tmp/lucidcode

# --- install the GitHub App itself ---
WORKDIR /app
COPY extensions/github-app/package.json extensions/github-app/package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY extensions/github-app/ ./

ENV LUCID_PYTHON=python
EXPOSE 3000
CMD ["npm", "start"]
