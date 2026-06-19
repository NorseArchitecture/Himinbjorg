# CLAUDE.md — Himinbjorg (`Norse.Identity`)

## 0. Wrong Root — Halt

If you are reading this because **Himinbjorg itself is the Claude Code session root** — someone ran `claude` from inside this directory instead of `../Bifrost` — stop here. Do not read further, do not propose changes, do not run anything.

Tell the user: every Norse Architecture session starts from **Bifrost**. Org-wide settings (the `superpowers` plugin, permission rules) only apply when Bifrost is the actual session root — Claude Code never merges a submodule's own `.claude/settings.json` into a parent-launched session. Exit, `cd ../Bifrost`, and run `claude` there instead.

This repo's own `.claude/settings.json` carries a `SessionStart` hook that should already have blocked this session before this file was ever read. If you're reading this anyway, hooks were bypassed, disabled, or failed — halt regardless; this rule does not depend on the hook to hold.

---

> **Do not commit, push, or rewrite git history.** Stage edits (`git add`), show the diff, and stop — the human reviews and commits.

> **Use US English spelling** in code, identifiers, comments, docs, and commit/PR copy.

## 1. What This Repository Is

Himinbjorg is **backend-only EF persistence** — `Norse.Identity`: entities, conventions, and migrations for ASP.NET Identity and OpenIddict. It never crosses to WASM or MAUI — that boundary is load-bearing, not a convenience. In the dependency chain it rides on Urdarbrunnr's EF foundation and everything below; Heimdall rides on it.

This repo is currently a bare shell (LICENSE only) — no specs have converged here yet. Before writing any code: brainstorm → spec → plan, recorded in `../Glitnir/docs/superpowers/`, per the org's spec-first discipline. Do not scaffold a project structure ahead of a converged spec.

See `../Bifrost/CLAUDE.md` (§2 The Naming Model) and `../Glitnir/CLAUDE.md` (§1 Bounded Context Map) for the full realm table and how Himinbjorg fits the rest of the cosmos.
