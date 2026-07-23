"""Preserve ``python -m evoom_guard.cli`` after the atomic package migration."""

from evoom_guard.cli import main

raise SystemExit(main())
