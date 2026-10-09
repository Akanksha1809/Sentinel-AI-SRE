# syntax=docker/dockerfile:1
# Shared image for the Python services in the uv workspace.
#   PACKAGE: workspace package to install (sentinel | shop-api | sentinel-actuator | sentinel-loadgen)
#   MODULE:  python module to run (`python -m $MODULE`)
#   RELEASE_DEFECT / APP_VERSION: baked-in release identity (shop-api only)
#   HEALTHCHECK_URL: polled by the image HEALTHCHECK

FROM ghcr.io/astral-sh/uv:0.12.24 AS uv

FROM python:3.12.15-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
ARG PACKAGE
WORKDIR /src
# Dependency layer: only lock + manifests, so code edits don't bust the cache.
COPY pyproject.toml uv.lock README.md ./
COPY services/demo-app/pyproject.toml services/demo-app/
COPY services/actuator/pyproject.toml services/actuator/
COPY services/loadgen/pyproject.toml services/loadgen/
RUN uv sync --frozen --no-dev --package "${PACKAGE}" --no-install-workspace
COPY src/ src/
COPY services/ services/
RUN uv sync --frozen --no-dev --package "${PACKAGE}" --no-editable

FROM python:3.12.15-slim
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /opt/venv /opt/venv
COPY runbooks/ /opt/sentinel/runbooks/
ARG MODULE
ARG RELEASE_DEFECT=none
ARG APP_VERSION=0.0.0
ARG HEALTHCHECK_URL=http://127.0.0.1:8000/healthz
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_MODULE=${MODULE} \
    RELEASE_DEFECT=${RELEASE_DEFECT} \
    APP_VERSION=${APP_VERSION} \
    HEALTHCHECK_URL=${HEALTHCHECK_URL}
USER 10001
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen(os.environ['HEALTHCHECK_URL'], timeout=2)"]
CMD ["/bin/sh", "-c", "exec python -m \"$APP_MODULE\""]
