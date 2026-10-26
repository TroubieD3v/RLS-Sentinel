# syntax=docker/dockerfile:1.7
# Single image: API + bundled web UI + synthetic fixtures. It contains no PostgreSQL server and no secrets.

FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS wheel
WORKDIR /src
RUN pip install --no-cache-dir build
COPY backend ./backend
COPY fixtures ./fixtures
COPY --from=ui /ui/dist ./ui-dist
RUN mkdir -p backend/rls_sentinel/_bundled \
 && cp -r ui-dist backend/rls_sentinel/_bundled/ui \
 && cp -r fixtures backend/rls_sentinel/_bundled/fixtures \
 && printf '"""Build artefact."""\n' > backend/rls_sentinel/_bundled/__init__.py \
 && python -m build --wheel --outdir /wheels backend

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="RLS Sentinel" \
      org.opencontainers.image.description="PostgreSQL Row-Level Security verification platform" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --system --uid 10001 --create-home --home-dir /home/sentinel sentinel
COPY --from=wheel /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER 10001
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8787 \
    SENTINEL_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/v1/health', timeout=3).status == 200 else 1)"
ENTRYPOINT ["rls-sentinel"]
CMD ["serve"]
