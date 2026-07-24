# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
# The `sample_repo/` trees under examples/ are FIXTURES: their tests are meant to
# run INSIDE the Guard judge's copy (where the sample package is import-able), not
# from this repo's root. So a stray `pytest examples/` must not try to collect
# them. The judge is unaffected — it runs pytest from within the copied sample_repo.
# The case study's `fixtures/` regression test and its `work/` output are the
# same kind of artifact: they run inside the judged charset-normalizer copy.
collect_ignore_glob = ["*/sample_repo/*", "*/sample-repo/*", "*/fixtures/*", "*/work/*"]
