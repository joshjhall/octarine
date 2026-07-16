---
name: project_zed_entrypoint_recover
description: "Zed devcontainers replace the image ENTRYPOINT, so first-startup hooks (codegraph index, OP secrets, Zed config) need recover-entrypoint in postStartCommand"
metadata:
  node_type: memory
  type: project
  originSessionId: d54ed237-e323-4ddd-b13f-79a98d03a8a6
---

Zed's native devcontainer impl replaces the image ENTRYPOINT with a `sleep infinity` stub even with `"overrideCommand": false` (upstream zed#56357). The containers submodule runs one-time setup via the ENTRYPOINT's `/etc/container/first-startup/*.sh` — including `codegraph-index-first-startup.sh` (symlinks `.codegraph -> /cache/codegraph` + builds the index), OP secret resolution, and Zed LSP/agent config. Under Zed none of it runs.

**Fix pattern:** `postStartCommand` MUST start with `recover-entrypoint &&` (replays first-startup; fast-path no-op under VS Code via `~/.container-initialized` marker). Documented in `containers/docs/troubleshooting/zed-devcontainer.md`.

**Also:** never build the codegraph index from `post-create.sh` — it creates a real `.codegraph/` dir in the git tree that the submodule hook then refuses to clobber, defeating the `/cache/codegraph` volume. The submodule first-startup hook is the single source of truth.

**Why:** octarine's `.devcontainer/devcontainer.json` had drifted from the containers template (missing `recover-entrypoint`), so codegraph was never indexed under Zed. Fixed in #689 / PR #690.

**How to apply:** when auditing/editing `.devcontainer/devcontainer.json`, verify `postStartCommand` leads with `recover-entrypoint &&`. Relates to [[project_worktree_submodule_hooks]].
