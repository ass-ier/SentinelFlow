FROM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --ignore-scripts && npm rebuild esbuild
COPY frontend/ ./
RUN npm run build

FROM python:3.13.15-alpine3.24@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f AS dependencies
COPY requirements-runtime.lock /build/requirements-runtime.lock
RUN python -m pip install --no-cache-dir --require-hashes --target /opt/python -r /build/requirements-runtime.lock

FROM python:3.13.15-alpine3.24@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f
WORKDIR /srv/sentinelflow
# Installers and their bundled libraries are not required by the running application.
RUN python -m pip uninstall --yes pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && addgroup -g 10001 sentinel \
    && adduser -D -u 10001 -G sentinel sentinel
COPY --from=dependencies /opt/python /opt/python
COPY requirements-runtime.lock pyproject.toml ./
COPY backend/app ./backend/app
COPY scripts ./scripts
COPY rules ./rules
COPY test-data ./test-data
COPY docs ./docs
COPY README.md LICENSE ./
COPY --from=frontend /build/dist ./frontend/dist
COPY --from=frontend /build/public/favicon.svg ./frontend/public/favicon.svg
RUN mkdir -p data artifacts && chown sentinel:sentinel data artifacts
USER sentinel
ENV PORT=8765 \
    PYTHONPATH=/opt/python:/srv/sentinelflow/backend \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 8765
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json,os,urllib.request; r=json.load(urllib.request.urlopen('http://127.0.0.1:'+str(int(os.getenv('PORT','8765')))+'/health',timeout=3)); assert r['status']=='ok'"
CMD ["python", "scripts/serve.py"]
