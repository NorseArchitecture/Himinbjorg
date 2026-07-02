# Himinbjörg

> Himinbjörg — Heimdall's hall at the head of Bifröst.

![Himinbjörg — Heimdall's hall where heaven meets the bridge, standing watch at the edge of the nine realms](https://github.com/user-attachments/assets/d38e6d83-bbdd-465b-93ed-ad42b06934af "Himinbjörg — Heimdall's hall at the head of Bifröst")

*Image credit: [@norsemythologyclips](https://www.instagram.com/norsemythologyclips/) — go follow them.*

The backend-only identity store of the Norse Architecture — **`Norse.Identity`**: EF Core model, conventions, and migrations for ASP.NET Identity and OpenIddict. Entities stay server-side and never cross into WASM or MAUI — that boundary is load-bearing, not a convenience. In the dependency chain it rides on Urdarbrunnr's EF foundation and everything below; Heimdall rides on it.

## Status

**Live:** `Norse.Identity` and `Norse.Identity.Migrations` — the full ASP.NET Core Identity v3 + OpenIddict entity set, `NorseIdentityDbContext`, `NorseUserStore`, and a real EF migration (`InitialCreate`) that stands up `norse_identity` end to end via the platform migrations service (the full story is on [Bifröst's README](https://github.com/NorseArchitecture/Bifrost#readme)). Identity was chosen as the proving vehicle for the whole migrations framework precisely because its schema is well-known and its base classes are unforgiving — if the framework survives ASP.NET Core Identity, it survives anything. Design for what comes next (Heimdall's auth surface rides on this) happens first: brainstorm → spec → plan, recorded in Glitnir's `docs/Himinbjorg/`.

## The cosmos

Himinbjörg is one realm of the [Norse Architecture](https://github.com/NorseArchitecture). The whole platform composes at [Bifröst](https://github.com/NorseArchitecture/Bifrost) — clone once, cross the bridge, and every session starts there so decisions get brainstormed across the entire landscape, not in isolation. Every design is tried in [Glitnir](https://github.com/NorseArchitecture/Glitnir), the design court, before code is forged here; this realm's specs and plans will live in the court's [docs/Himinbjorg/](https://github.com/NorseArchitecture/Glitnir/tree/master/docs/Himinbjorg) once they converge.

## Soundtrack: Himinbjörg
[![Soundtrack: Himinbjörg](https://img.youtube.com/vi/clUFrvQ-a4U/maxresdefault.jpg)](https://www.youtube.com/watch?v=clUFrvQ-a4U)
