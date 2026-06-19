# Himinbjorg

> Himinbjörg — Heimdall's hall at the head of Bifrost.

The backend-only identity store of the Norse Architecture — **`Norse.Identity`**: EF Core model, conventions, and migrations for ASP.NET Identity and OpenIddict. Entities stay server-side and never cross into WASM or MAUI — that boundary is load-bearing, not a convenience. In the dependency chain it rides on Urdarbrunnr's EF foundation and everything below; Heimdall rides on it.

## Status

This realm is currently a bare shell — no code, no specs converged yet. Design happens first: brainstorm → spec → plan, recorded in Glitnir's `docs/Himinbjorg/`, before any project is scaffolded here.

## The cosmos

Himinbjorg is one realm of the [Norse Architecture](https://github.com/NorseArchitecture). The whole platform composes at [Bifrost](https://github.com/NorseArchitecture/Bifrost) — clone once, cross the bridge, and every session starts there so decisions get brainstormed across the entire landscape, not in isolation. Every design is tried in [Glitnir](https://github.com/NorseArchitecture/Glitnir), the design court, before code is forged here; this realm's specs and plans will live in the court's `docs/Himinbjorg/` once they converge.
