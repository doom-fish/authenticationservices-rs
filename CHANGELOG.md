# Changelog

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
