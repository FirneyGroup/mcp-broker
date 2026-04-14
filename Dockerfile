FROM python:3.11-slim

WORKDIR /app

# Copy source and config (needed for setuptools package discovery)
COPY pyproject.toml .
COPY src/ src/

# Install dependencies
RUN pip install --no-cache-dir ".[all]"

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

RUN useradd -m -u 1000 appuser && mkdir -p /app/data && chown appuser:appuser /app/data
USER appuser

EXPOSE 8002

# NOTE: --forwarded-allow-ips should be restricted to known proxy IPs in production
CMD ["uvicorn", "broker.main:app", "--host", "0.0.0.0", "--port", "8002", "--proxy-headers", "--forwarded-allow-ips", "*"]
