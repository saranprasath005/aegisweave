FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock && useradd --create-home --uid 10001 aegis
COPY aegisweave ./aegisweave
COPY experiments ./experiments
COPY frontend ./frontend
COPY config ./config
# Deterministic, explicitly synthetic demo model (seed 42), root-owned so the service
# account cannot replace the artifact it loads. Replace with a verified artifact for real use.
RUN python -m aegisweave train-demo --model /app/models/active > /app/models-train.log && \
    mkdir -p /app/var && chown -R aegis:aegis /app/var
ENV AEGISWEAVE_MODEL=/app/models/active
USER aegis
EXPOSE 8765
# Fails when the service reports degraded (e.g. no loadable model), not only when HTTP is down.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import json,urllib.request,sys; sys.exit(json.load(urllib.request.urlopen('http://127.0.0.1:8765/api/health',timeout=3)).get('status')!='healthy')"
CMD ["python", "-m", "aegisweave", "serve", "--host", "0.0.0.0"]
