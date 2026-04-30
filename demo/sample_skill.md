---
name: doc_reader
description: Reads documentation and summarizes findings for the agent.
permissions:
  - filesystem:read
  - environment:read
---

# Doc reader skill

This skill loads markdown from the workspace and produces a short summary.

> **Note:** This file is bundled for local smoke tests. The interactive dashboard preview
> lives under `demo/ui` — see `demo/README.md`.
