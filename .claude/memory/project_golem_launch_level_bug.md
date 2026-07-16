---
name: project_golem_launch_level_bug
description: "golem-launch.sh hardcodes --level 4 and ignores any --level arg, so every dispatched golem runs L4 regardless of requested level"
metadata:
  node_type: memory
  type: project
  originSessionId: d54ed237-e323-4ddd-b13f-79a98d03a8a6
---

`/opt/librarian/plugins/workflow/scripts/golem-launch.sh` (workflow plugin, NOT the octarine repo — the dir is not a git repo, so file against the librarian/workflow plugin backlog) has a level bug:

- The launch string hardcodes `--level 4`: `claude --permission-mode auto '/workflow:next-issue $n --level 4'` (script lines ~337 and ~99).
- It parses only `N="${2:-}"` and reads no further args, so `golem-launch.sh launch <N> --level 3` **silently drops** the `--level 3`.

**Consequence:** every golem dispatched via this launcher runs at **L4** (fully autonomous, no plan gate) regardless of the level requested. L1–L3 dispatch is unreachable through this path. Confirmed 2026-07-15: dispatched #426/#405/#407 at `--level 3`; all three ran `/workflow:next-issue … --level 4` → `plan_gated=false`, no ExitPlanMode stop, straight to PRs.

**Fix (small):** forward trailing args (or an explicit `--level N`) from `golem-launch.sh` into the launch string instead of the literal `4`. `worktree-new.sh`'s printed hint also shows `--level 4` as a template default.

**How to apply / workaround:** until fixed, to actually run below L4, don't rely on golem-launch.sh's `--level` passthrough — edit the launch invocation to embed the intended level, or run the bare `tmux new-session` line yourself with the correct `--level N`. Relates to [[feedback_l3_merge_authority.md]] and the missing `just golem-attach` root-justfile alias (containers/justfile has `golem-attach N` but octarine root doesn't import it).
