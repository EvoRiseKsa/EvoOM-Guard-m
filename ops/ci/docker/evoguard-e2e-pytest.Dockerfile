# This Dockerfile is a CI test fixture, not a product runtime image.
# The default is a reviewed immutable OCI index; CI passes the same value as an
# explicit build argument so the candidate and pytest-bearing images stay bound.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
FROM ${PYTHON_IMAGE}

COPY requirements/docker-pytest.lock /tmp/docker-pytest.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tmp/docker-pytest.lock
