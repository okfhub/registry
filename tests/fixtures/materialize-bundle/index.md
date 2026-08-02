---
title: Materialize Fixture Bundle
---

# Materialize Fixture

A reserved `index.md` (no `type` frontmatter) — parseBundle must SKIP it (it is
not a concept). This committed fixture documents the expected bundle shape for
the materialization tests; the runtime tests build hermetic tmp bundles
(mirroring tests/checks/structure.test.mjs) so they do not depend on reading
this file at test time.
