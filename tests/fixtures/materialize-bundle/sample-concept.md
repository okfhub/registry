---
type: metric
title: Sample Concept
---

# Sample Concept

This committed fixture documents the materialization contract: a concept `.md`
with frontmatter `{ type: metric }` and a body. computeEvidence →
materializeConcepts reads such files verbatim (frontmatter + body) as the `body`
field so the gateway can serve them as `text/markdown` MCP resources (D-04/D-05).
The runtime tests build hermetic tmp bundles rather than reading this file.
