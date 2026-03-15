FROM python:3.11-slim

WORKDIR /app
COPY backend.py /app/backend.py

RUN useradd -m appuser && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

ENV AGENTOPS_HOST=0.0.0.0
ENV AGENTOPS_PORT=8080
ENV AGENTOPS_DB_PATH=/data/agentops.db

EXPOSE 8080
CMD ["python", "backend.py"]
