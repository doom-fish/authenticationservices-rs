# Changelog

All notable changes to `authenticationservices-rs` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - Unreleased

### Security

- `WebAuthenticationSessionGuard` and `AuthorizationGuard` handed Swift a
  borrowed pointer to state they freed on drop, so `guard.cancel();
  drop(guard)` let the completion or delegate write into freed memory. Swift
  now owns a `CallbackContext` reference, and results that arrive after the
  guard is dropped are discarded.
- `Debug` for `Authorization`, `AppleIdCredential`, `PasswordCredential` and
  the passkey and security-key assertion types printed identity tokens,
  authorization codes, passwords, signatures, user handles, PRF outputs and
  large-blob data. These fields now print as `<redacted>`.
- A passkey or security-key request built without a challenge used an empty
  one, which makes the assertion replayable. A missing or empty challenge is
  now `InvalidArgument`.
- Request handles were `Send + Sync` while `update(&self)` mutates the request
  objects that the authorization controller reads on the main thread.
  `update` now returns `InvalidArgument` while an authorization controller
  still holds the request, including perform or cancel work already queued on
  the main queue.
- The Swift bridge unboxed request, controller, credential, descriptor and
  web-session handles without checking their class, so a handle of the wrong
  type was reinterpreted as the expected one. Every bridge function now checks
  the class (`as?`) and a mismatch is `AuthenticationServicesError::InvalidArgument`.
- Identity tokens, authorization codes, passwords, PRF outputs and large-blob
  data were plain `String`/`Vec<u8>` values that were never wiped and were
  compared with derived, variable-time `PartialEq`. They are `Zeroizing` now
  and compare in constant time, and the bridge's JSON buffer that carries an
  authorization or password credential is wiped before it is freed.

### Fixed

- `CredentialIdentityStore::save_identities`, `remove_identities`,
  `replace_identities`, `remove_all_identities` and
  `credential_identities_for_service` always returned `NotSupported` while
  `is_supported()` reported `true`. They now call `ASCredentialIdentityStore`;
  passkey identities need macOS 14 and a user handle, listing macOS 14.4,
  one-time-code identities macOS 15, and service identifiers and display
  names macOS 26.2.
- A synchronous call that timed out after 30 s left its Swift task running,
  and the late result was written into shared state without a lock. The task
  is now cancelled and a late result is discarded.
- `update` on a passkey or security-key request silently ignored a new
  challenge or client data. Changing either now returns `InvalidArgument`;
  `None` or the current value is accepted.
- `AuthorizationGuard::cancel` did nothing on macOS 12; it returns
  `NotSupported` there now. Failures while creating an authorization
  controller (no request, a missing callback, a handle of the wrong type) were
  reported as `FrameworkError` and are `InvalidArgument` now.
- `update` ignored changes to the user ID and name of passkey and
  security-key registrations and to the display name of security-key
  registrations; they are applied now. Inputs left as `None` or empty (allowed
  and excluded credentials, credential parameters, large-blob and PRF inputs,
  the security-key `appID` and the passkey `requestStyle`) are cleared
  instead of keeping their previous value.
- Large-blob inputs on macOS 13 and PRF inputs on macOS 14 or older were
  silently dropped. A request that sets them returns `NotSupported` now.
- `WebAuthenticationSession::start` called off the main thread blocked on
  `DispatchQueue.main.sync`, which deadlocks while the main thread waits for
  that caller. It returns `AuthenticationServicesError::MainThreadRequired`
  now, and so does the async `start`.

### Changed

- **Breaking:** `client_data` in `PlatformPasskeyRegistrationOptions`,
  `PlatformPasskeyAssertionOptions`, `SecurityKeyRegistrationOptions` and
  `SecurityKeyAssertionOptions` is `Option<PublicKeyCredentialClientData>`
  (was `Option<Vec<u8>>`). Requests are created from it instead of rejecting
  it: platform requests need macOS 13.5, security-key requests macOS 14.4.
  A challenge that contradicts `client_data.challenge` is rejected.
- **Breaking:** `AppleIdRequest`, `PasswordRequest`,
  `PasskeyRegistrationRequest`, `PasskeyAssertionRequest`,
  `SecurityKeyRegistrationRequest` and `SecurityKeyAssertionRequest` are
  `Send` but no longer `Sync`.
- **Breaking:** request constructors return `InvalidArgument` for a missing or
  empty challenge.
- **Breaking:** `AuthorizationGuard::cancel` and
  `WebAuthenticationSessionGuard::cancel` return
  `Result<(), AuthenticationServicesError>`, and
  `AuthorizationGuard::request_count` returns
  `Result<usize, AuthenticationServicesError>`.
- **Breaking:** `update` on `PasskeyRegistrationRequest`,
  `PasskeyAssertionRequest`, `SecurityKeyRegistrationRequest` and
  `SecurityKeyAssertionRequest` applies the whole configuration; start from
  `configuration()` and change the fields you need.
- **Breaking:** registration requests and their `update` reject a user ID
  that is empty or longer than 64 bytes with `InvalidArgument`.
- **Breaking:** `AuthenticationServicesError` is `#[non_exhaustive]` and has a
  new `MainThreadRequired` variant, returned by `WebAuthenticationSession::start`
  and `AsyncWebAuthenticationSession::start` off the main thread.
- Dropping `AuthorizationGuard` or `WebAuthenticationSessionGuard` now cancels
  the controller or session.
- **Breaking:** `Authorization::{identity_token, authorization_code,
  password, large_blob_data, prf_first, prf_second}` and
  `AppleIdCredential::{identity_token, authorization_code}` are
  `Option<Zeroizing<String>>`, `PasswordCredential::password` is
  `Zeroizing<String>`, `PrfOutput::{first, second}` are
  `Option<Zeroizing<Vec<u8>>>`, and `LargeBlobAssertionOutputResult::Read`
  holds `Zeroizing<Vec<u8>>`.
- `doom-fish-utils` requirement is now `>=0.4.1, <0.5`.
- New dependency `zeroize` (`>=1.6, <1.9` with its `serde` feature; 1.9 needs
  Rust 1.85).
- `rust-version` is now 1.82.

## [0.3.2] - 2026-06-06

### Fixed

- Guarded the AuthenticationServices delegate trampolines against panics
  crossing the FFI boundary and removed the vestigial Swift bridge C header.

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
