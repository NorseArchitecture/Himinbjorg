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

**Both assemblies are live**, shipped, tagged, and published to NuGet as Tasks 7–8 of the cross-realm migrations framework rollout (`../Glitnir/docs/Platform/plans/2026-06-28-migrations-framework-identity-schema.md`). `Norse.Identity` carries the full ASP.NET Core Identity v3 entity set (`NorseUser`, `NorseRole`, `NorseUserClaim`, `NorseUserRole`, `NorseUserLogin`, `NorseUserToken`, `NorseRoleClaim`, `NorseUserPasskey`), `NorseIdentityDbContext` (Identity and OpenIddict combined via `builder.UseOpenIddict<Guid>()`), and `NorseUserStore`. `Norse.Identity.Migrations` carries `NorseIdentityMigrationContributor`, a design-time `IDesignTimeDbContextFactory`, and a real EF migration (`InitialCreate`) that stands up `norse_identity` end to end.

Identity was chosen as this framework's proving vehicle deliberately: its schema is well-known and its base classes are unforgiving, so if the migrations framework survives ASP.NET Core Identity it survives anything. It nearly didn't survive gracefully — one gotcha worth knowing before touching `NorseIdentityDbContext`: ASP.NET Core Identity decides its schema shape (`Version1` vs `Version3`, i.e. whether the passkey table exists) by reading `IOptions<IdentityOptions>` off the context's `ApplicationServiceProvider`. A caller that registers `NorseIdentityDbContext` without the full `AddNorseIdentity()` DI surface — exactly what the migrations service does, since it only needs the context to migrate — would otherwise silently get `Version1` and lose the passkey table. `NorseIdentityDbContext.OnConfiguring` carries a fallback `IServiceProvider` that forces `Version3` for that path; read the type's doc comment before "fixing" it away.

Every subsequent plan for this realm follows the same discipline: brainstorm → spec → plan, recorded in `../Glitnir/docs/Himinbjorg/`, per the org's spec-first discipline. Do not scaffold ahead of a converged spec. When that plan is written, its REQUIRED SUB-SKILL line names `superpowers:subagent-driven-development` as the default (not a recommendation among equals — `executing-plans` is the narrow fallback for separate-session review checkpoints) paired with `superpowers:test-driven-development` — implementation here is subagent-orchestrated and test-driven, never one without the other (`../Glitnir/CLAUDE.md` §2.8).

See `../Bifrost/CLAUDE.md` (§2 The Naming Model) and `../Glitnir/CLAUDE.md` (§1 Bounded Context Map) for the full realm table and how Himinbjorg fits the rest of the cosmos.
