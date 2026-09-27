FROM node:20.19.2-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13.7-slim
WORKDIR /srv/sentinelflow
COPY requirements.lock pyproject.toml ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY backend ./backend
COPY scripts ./scripts
COPY rules ./rules
COPY test-data ./test-data
COPY docs ./docs
COPY README.md LICENSE ./
COPY --from=frontend /build/dist ./frontend/dist
RUN python -m pip install --no-deps --no-build-isolation -e . \
    && useradd --uid 10001 --create-home sentinel \
    && mkdir -p data artifacts \
    && chown -R sentinel:sentinel data artifacts
USER sentinel
EXPOSE 8765
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765"]
