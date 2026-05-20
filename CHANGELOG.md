# Changelog

## [0.3.1] - 2026-05-20

- Migrated local `take_string` body to call `doom_fish_utils::ffi_string::take_owned_cstring_c`. Centralises the duplicated FFI take-string pattern fleet-wide. No public API change.

## [0.3.0] - 2026-05-20

### Added

- `async_api` module behind the `async` feature, providing executor-agnostic async wrappers for `ASAuthorizationController` request flows and `ASWebAuthenticationSession` completions. Uses `doom-fish-utils::completion`.

## [0.2.4] - 2026-05-19

- Bump MSRV from 1.70 to 1.76 to match fleet baseline.

## [0.2.3] - 2026-05-17

### Changed

- Fixed 8 doc comment link escaping issues in module-level documentation to eliminate rustdoc warnings.

## [0.2.2] - 2026-05-17

### Changed

- Closed audit-v2 gap by marking `ASAuthorizationAppleIDButton` as EXEMPT. The button is an `NSControl` subclass on macOS which requires AppKit interop; the doom-fish family avoids pulling AppKit dependencies in favor of objc2 direct bindings. Since `AuthorizationController` provides all practical authentication flows without requiring the button, the crate maintains 100% effective coverage.

## [0.2.1] - 2026-05-17

### Added

- Added `authorization_apple_id_button`, `authorization_types`, `foundation_types`, `authorization_provider_extension`, `authorization_single_sign_on`, `authorization_web_browser`, and `credential_provider` modules to close the MacOSX26.2 AuthenticationServices audit.
- Added Apple ID button helpers, shared authorization/public-key/credential traits, ASFoundation aliases, NSError-domain helpers, and COSE/client-data wrappers.
- Added Rust-side models for provider-extension / Platform SSO, single sign-on, credential-provider / passkey extension, and web-browser public-key-credential request families.
- Added smoke tests covering the new Apple ID button, provider-extension, single sign-on, web-browser, credential-provider, and shared-surface APIs.

### Changed

- Extended Apple ID authorization payload decoding with `real_user_status` and `user_age_range`.
- Bumped crate version to `0.2.1` and drove `COVERAGE_AUDIT.md` to 100% coverage.

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
