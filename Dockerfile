FROM python:3.15-slim AS build

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /venv \
    && /venv/bin/pip install . \
    && /venv/bin/pip uninstall -y pip

FROM python:3.15-slim

# Nothing installs packages at runtime: drop pip, its bundled wheel, and the
# interpreter's dev tools so they aren't shipped (or scanned) in the image.
RUN rm -rf /usr/local/lib/python3.*/site-packages/pip \
           /usr/local/lib/python3.*/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.*/ensurepip \
           /usr/local/lib/python3.*/idlelib \
           /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc*

ENV PATH=/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=build /venv /venv

USER 65534:65534
EXPOSE 9019
ENTRYPOINT ["domain-expiry"]
