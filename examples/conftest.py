# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
# The `sample_repo/` trees under examples/ are FIXTURES: their tests are meant to
# run INSIDE the Guard judge's copy (where the sample package is import-able), not
# from this repo's root. So a stray `pytest examples/` must not try to collect
# them. The judge is unaffected — it runs pytest from within the copied sample_repo.
collect_ignore_glob = ["*/sample_repo/*", "*/sample-repo/*"]
