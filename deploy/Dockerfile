FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock && useradd --create-home --uid 10001 aegis
COPY aegisweave ./aegisweave
COPY frontend ./frontend
COPY config ./config
RUN mkdir -p /app/var && chown aegis:aegis /app/var
USER aegis
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import json,urllib.request,sys; sys.exit(json.load(urllib.request.urlopen('http://127.0.0.1:8765/api/health',timeout=3)).get('status')!='healthy')"
CMD ["python", "-m", "aegisweave", "serve", "--host", "0.0.0.0", "--model", "/models/active", "--require-real-model", "--config", "/app/config/site.json"]
