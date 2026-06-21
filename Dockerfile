# loglens dashboard image — slim, runs `loglens serve`.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first (better layer caching), then the package.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[web]"

# Non-root runtime user; /logs is the directory the dashboard browses/tails.
RUN useradd --create-home --uid 10001 loglens \
    && mkdir -p /logs && chown -R loglens:loglens /logs
USER loglens

EXPOSE 8000
ENV LOGLENS_PROVIDER=ollama
HEALTHCHECK --interval=10s --timeout=3s --retries=10 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)"

CMD ["loglens", "serve", "--host", "0.0.0.0", "--port", "8000", "--logs-dir", "/logs"]
