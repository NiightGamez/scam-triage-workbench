# Multi-stage hardened container for Scam Triage Workbench
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install dependencies into wheels / virtual environment
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal, hardened runtime stage
FROM python:3.12-slim AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PATH="/home/appuser/.local/bin:$PATH"

# Create unprivileged system user without shell or sudo privileges
RUN groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -d /home/appuser -s /sbin/nologin appuser && \
    mkdir -p /home/appuser /app && \
    chown -R appuser:appuser /home/appuser

WORKDIR /app

# Copy installed Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local
RUN chown -R appuser:appuser /home/appuser/.local

# Copy application source code
COPY --chown=root:root triage/ ./triage/
COPY --chown=root:root api/ ./api/
COPY --chown=root:root static/ ./static/
COPY --chown=root:root app.py triage.py README.md ./

# Set strict read-only permissions across /app (no write permissions for appuser)
RUN chmod -R 555 /app

# Switch to unprivileged non-root user
USER appuser

EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

# Launch FastAPI via Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
