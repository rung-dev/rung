# A pinned, offline-friendly image with rung preinstalled, for CI gating on
# runners that pull a container instead of pip-installing. Built from source (the
# tagged tree), so it does not depend on PyPI having published yet. Only the
# public packaging inputs are copied in; nothing gitignored enters the image.
FROM python:3.12-slim

WORKDIR /pkg
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# Build backend (hatchling) is fetched into an isolated, discarded build env; the
# installed runtime is stdlib-only and dependency-free.
RUN pip install --no-cache-dir . && rm -rf /pkg
WORKDIR /

# `docker run ghcr.io/rung-dev/rung gate bundle.json`; the container exit code is
# the gate verdict (0 pass, 30 block, 2 cannot-evaluate).
ENTRYPOINT ["rung"]
