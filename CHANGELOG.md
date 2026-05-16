# Changelog

## [0.2.0] - 2026-05-16

### Added

- Expanded Swift bridge coverage into logical-area files for authorization control, Apple ID, password credentials, passkeys/security keys, credential identity store, settings helpers, and web authentication sessions.
- Added Rust modules for `AuthorizationController`, `AppleIdProvider`, `PasswordCredential`, `AuthorizationProvider` helpers, passkey/security-key request families, `CredentialIdentityStore`, `SettingsHelper`, and explicit account-family placeholders.
- Added compatibility re-export shims for the original `authorization`, `provider`, and `web_auth_session` entry points.
- Added per-area examples under `examples/02_*` through `examples/11_*` plus expanded smoke coverage.
- Added integration tests covering Apple ID helpers, authorization-provider metadata, password credentials, authorization result decoding, passkey descriptors, web-auth callbacks, credential identity store state, account placeholders, account-auth-modification placeholders, and settings helper wrappers.
- Added `COVERAGE.md` documenting current API coverage and macOS limitations.

### Changed

- Bumped crate version to `0.2.0`.
- Updated README status, highlights, examples, and platform-limitation guidance.
- Promoted account/auth-modification support from “deferred” to explicit macOS placeholder coverage.

### Notes

- `ASCredentialIdentityStore` mutation/listing operations and macOS-unavailable account-authentication-modification APIs currently return `AuthenticationServicesError::NotSupported` with consistent bridge messages.
- Newer AuthenticationServices features remain gated by the macOS version exposed by the runtime SDK.

## [0.1.0] - 2025-01-01

### Added

- Initial `authenticationservices-rs` release.
- `AppleIdProvider` + `AppleIdRequest` wrapping `ASAuthorizationAppleIDProvider`.
- `PasswordProvider` + `PasswordRequest` wrapping `ASAuthorizationPasswordProvider`.
- `PlatformPublicKeyCredentialProvider` with passkey registration and assertion request builders.
- `AuthorizationController` wrapping `ASAuthorizationController` with callback observer/guard.
- `Authorization` + `AppleIdCredential` result types.
- `WebAuthenticationSession` wrapping `ASWebAuthenticationSession`.
- Smoke example `examples/01_authenticationservices_smoke.rs`.

### Deferred

- `ASAccountAuthenticationModificationController` — planned for v0.2.
