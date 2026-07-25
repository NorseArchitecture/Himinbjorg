# Norse.Identity.Web.Server

The full ASP.NET Core Identity v3 + OpenIddict entity set (`NorseUser`, `NorseRole`, `NorseUserClaim`, `NorseUserRole`, `NorseUserLogin`, `NorseUserToken`, `NorseRoleClaim`, `NorseUserPasskey`), `NorseIdentityDbContext`, `NorseUserStore`, and `NorseSignInManager` — plus, since PR #27, `IAuthenticationService`'s gRPC implementation over that store. Handlers work entirely in `Outcome<T>` (Asgard's mediator law); the forwarder decomposes failure via Midgard's `Infrastructure.Web.Server`, never by hand. `AddNorseAuthenticationService(connectionString)` is the single composition-root entry point a host calls to pull in the `DbContext`, ASP.NET Core Identity (with the `NorseSignInManager` override), the FluentValidation validators, the mediator handlers, and the service itself.

Always runs inside an HTTP context, bound into Yggdrasil's `Hosting.Web.Server` process — never referenced from WASM or MAUI. Also still carries the original Yggdrasil-scaffolded `/Account` and `/Account/Manage` Razor page tree (`Components/Pages/**`); those routes are being migrated out to Heimdall's `AuthN.Components`/`AuthN.Components.FluentUI` component by component, not all at once, so expect this project's UI surface to keep shrinking.

Part of the [Norse Architecture](https://github.com/NorseArchitecture) platform.
