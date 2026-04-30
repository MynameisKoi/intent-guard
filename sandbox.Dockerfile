# Minimal image used by engine.agents.sandbox for dry-runs (timeout-guarded).
FROM python:3.12-slim-bookworm
WORKDIR /workspace
RUN pip install --no-cache-dir requests
ENV PYTHONUNBUFFERED=1
CMD ["python", "-c", "print('intentguard-sandbox ready')"]
