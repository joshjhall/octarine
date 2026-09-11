---
name: project_rumdl_version_skew
description: CI pins rumdl 0.1.91 but the devcontainer ships 0.2.68; a line starting with `#123` passes locally and fails MD032 on CI
metadata:
  type: project
---

`just lint-md` can pass locally and fail on CI: `.github/workflows/ci.yml`
pins rumdl **0.1.91** (matched to containers v4.19.0's dev-tools), while the
devcontainer currently has **0.2.68**. The older version parses a markdown line
beginning with a bare issue ref (`#667 covered ...`) as an ATX heading, so it
reports `MD032 List should be followed by blank line` on the preceding list.

**Why:** the two binaries disagree on heading detection, and the local one is
newer/more lenient — so a clean local `just lint-md` is not proof CI will pass.

**How to apply:** never start a markdown line with `#<digits>`; write `PR #667`
or `issue #667`. The x86_64 rumdl release tarball will NOT run on the ARM
devcontainer (`qemu: Could not open /lib64/ld-linux-x86-64.so.2`), so you cannot
reproduce the pinned version locally — read the CI log instead. Related:
[[project_ci_doc_job_strict]], [[project_devcontainer_clang_disk]].
