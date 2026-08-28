# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Suite-wide import priming for the lazily loaded platform command owners.

The ``evoom_guard.cli`` dispatch facade imports its platform command owners
lazily (function-locally) so a core-only distribution imports cleanly. The
test suite always runs against the full distribution, and several frozen
characterization vectors execute commands inside instrumented windows that
observe global seams (for example a patched ``os.path.abspath``). Under a
coverage tracer, a *first* import performed inside such a window records
tracer bookkeeping through those patched seams and drifts the frozen event
counts, purely as a function of test order.

Importing every owner once here moves all first-import side effects outside
every measured window, restoring the order-independence the vectors had when
the facade imported its owners eagerly. This primes the test environment
only; production laziness is unchanged and is proven separately by the
core-only installation checks and ``tests/architecture/test_license_boundaries.py``.
"""

from __future__ import annotations

import evoom_guard.cli.agent_change_commands  # noqa: F401
import evoom_guard.cli.artifact_admission_commands  # noqa: F401
import evoom_guard.cli.artifact_digest_admission_commands  # noqa: F401
import evoom_guard.cli.change_attempt_observation_commands  # noqa: F401
import evoom_guard.cli.evidence_sealing_commands  # noqa: F401
import evoom_guard.cli.finalizer_deployment_commands  # noqa: F401
import evoom_guard.cli.github_attestation_admission_commands  # noqa: F401
import evoom_guard.cli.github_attestation_receipt_commands  # noqa: F401
import evoom_guard.cli.release_artifact_admission_commands  # noqa: F401
import evoom_guard.cli.release_source_admission_commands  # noqa: F401
import evoom_guard.cli.release_source_finalizer_commands  # noqa: F401
import evoom_guard.cli.release_source_producer_receipt_commands  # noqa: F401
import evoom_guard.cli.trusted_finalizer_commands  # noqa: F401
