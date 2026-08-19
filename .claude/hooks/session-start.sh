#!/bin/bash
# ------------------------------------------------------------------------------
# EvoOM Guard — Claude Code on the web dependency bootstrap.
#
# Builds an isolated virtualenv (.venv) with the exact hash-locked CI/dev
# toolchain (pytest, ruff, mypy, coverage, cryptography, jsonschema) plus this
# package in editable mode, and makes it the session default, so a fresh web
# session can immediately run the same checks CI does:
#
#     python -m pytest -q
#     ruff check evoom_guard/ tests/
#     mypy evoom_guard/
#
# The locked set mirrors the "Install locked Python CI dependencies" step in
# .github/workflows/ci.yml, so the web session and CI resolve identically. A
# virtualenv is used (rather than a bare system install) so the toolchain never
# fights un-removable base-image system packages. The repository itself has no
# runtime dependencies.
# ------------------------------------------------------------------------------
set -euo pipefail

# Web sessions only: local developers manage their own environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Idempotent: reuse an existing venv, create it otherwise.
if [ ! -x .venv/bin/python ]; then
  python -m venv .venv
fi

.venv/bin/python -m pip install --upgrade --quiet pip
.venv/bin/python -m pip install \
  --only-binary=:all: --require-hashes -r requirements/ci.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .

# Make the venv the default interpreter for the rest of the session.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export VIRTUAL_ENV=\"${CLAUDE_PROJECT_DIR:-$PWD}/.venv\""
    echo "export PATH=\"${CLAUDE_PROJECT_DIR:-$PWD}/.venv/bin:\$PATH\""
  } >> "$CLAUDE_ENV_FILE"
fi
