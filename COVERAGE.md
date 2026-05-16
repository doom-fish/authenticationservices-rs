# AuthenticationServices coverage

## v0.2.0 matrix

| Area | Rust surface | Swift bridge | Status | Notes |
| --- | --- | --- | --- | --- |
| `ASAuthorizationController` | `authorization_controller` | `Authorization.swift` | ✅ | Controller creation, request bundles, request options, cancellation, decoded authorization payloads. |
| `ASWebAuthenticationSession` | `web_authentication_session` | `WebAuthSession.swift` | ✅ | Builder, callback matching, session inspection/start/cancel; HTTPS callback objects are macOS 14.4-gated. |
| `ASPasswordCredential` | `password_credential` | `PasswordCredential.swift` | ✅ | Credential creation + JSON decoding. |
| `ASAuthorizationAppleIDProvider` | `authorization_apple_id_provider` | `AuthorizationAppleIDProvider.swift` | ✅ | Request creation/update, configuration round-tripping, credential-state queries, revoked-notification name. |
| `ASAuthorizationProvider` / password provider | `authorization_provider` | `AuthorizationProvider.swift` | ✅ | Protocol metadata, supported kinds, password request creation/kind inspection. |
| Passkeys / public-key credentials / security keys | `authorization_passkey` | `AuthorizationPasskey.swift` | ✅ | Platform + security-key request builders, descriptor validation, decoded authorization payload helpers, large-blob/PRF availability gates. |
| `ASCredentialIdentityStore` | `credential_identity_store` | `CredentialIdentityStore.swift` | ⚠️ Partial | Store state is bridged on macOS. Rust models for password/passkey/OTP identities are present. Mutation/listing helpers currently return `NotSupported`. |
| Account request family (`ASAccount*`) | `account` | `Account.swift` | ⚠️ macOS placeholder | No standalone `ASAccount` API is exposed by the macOS SDK used for this crate; placeholder APIs return a consistent `NotSupported` error. |
| `ASAccountAuthenticationModificationController` | `account_authentication_modification_controller` | `AccountAuthenticationModificationController.swift` | ⚠️ macOS placeholder | Not exposed by the macOS SDK; wrapper is documented and returns `NotSupported`. |
| `ASSettingsHelper` | `settings_helper` | `SettingsHelper.swift` | ✅ | Support probing plus bridged helper entry points, with newer methods gated by OS availability. |

## Test and example coverage

- Examples: `examples/01_authenticationservices_smoke.rs` plus one area-focused example for each major module (`02_*` through `11_*`).
- Tests: integration tests under `tests/` cover each major module/area, including placeholder and partial-coverage behavior.

## Known macOS limitations

- `ASAccountAuthenticationModification*` is unavailable in the macOS AuthenticationServices SDK and is intentionally represented as a placeholder API surface.
- `ASCredentialIdentityStore` mutation/listing methods are not fully bridged yet; the Rust API returns `AuthenticationServicesError::NotSupported` with a stable message.
- Some newer APIs are OS-gated by Apple, including:
  - HTTPS callback matching for `ASWebAuthenticationSession.Callback` (macOS 14.4+)
  - several large-blob and PRF passkey properties (macOS 14+/15+)
  - `ASSettingsHelper.requestToTurnOnCredentialProviderExtension()` (macOS 15+)
