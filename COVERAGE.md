# AuthenticationServices coverage

## Matrix

"Rust models" rows are Rust-side data types, enums and traits that make no framework calls.

| Area | Rust surface | Swift bridge | Status | Notes |
| --- | --- | --- | --- | --- |
| Core authorization / Apple ID / password / passkeys | `authorization_controller`, `authorization_apple_id_provider`, `authorization_provider`, `password_credential`, `authorization_passkey` | `Authorization.swift`, `AuthorizationAppleIDProvider.swift`, `AuthorizationProvider.swift`, `PasswordCredential.swift`, `AuthorizationPasskey.swift` | ✅ | Covers the controller/request/credential surfaces plus Apple ID real-user-status / age-range decoding. WebAuthn requests require a non-empty challenge and accept client data (passkeys macOS 13.5+, security keys macOS 14.4+). Request handles are `Send` but not `Sync`, and `update` is refused while a controller holds the request. |
| `ASWebAuthenticationSession` | `web_authentication_session` | `WebAuthSession.swift`, `ErrorDomains.swift` | ✅ | Builder, callback matching, session inspection/start/cancel, request metadata helpers, and NSError-domain accessors. |
| Apple ID button / shared aliases / traits | `authorization_apple_id_button`, `authorization_types`, `foundation_types` | `ErrorDomains.swift` | ✅ | Covers Apple ID button helpers, shared authorization/public-key/credential traits, OpenID aliases, and ASFoundation aliases. The `ASAuthorizationAppleIDButton` view itself is not bridged. |
| Provider extension / Platform SSO | `authorization_provider_extension` | _None_ | ⚠️ Rust models | Models cover authorization requests/results, login configuration, login-manager state, enums, constants, and registration-handler traits. The macOS 27 SDK Platform SSO OpenID and token-exchange additions are not covered. |
| Single sign-on | `authorization_single_sign_on` | _None_ | ⚠️ Rust models | Covers SSO provider/request/credential helpers layered on the crate's OpenID request configuration. |
| Credential-provider / passkey extension helpers | `credential_provider` | _None_ | ⚠️ Rust models | Covers credential-provider request/credential/context/view-controller models, passkey extension inputs/outputs, client-data helpers, and COSE identifiers. |
| Web-browser public-key-credential helpers | `authorization_web_browser` | _None_ | ⚠️ Rust models | Covers browser-side public-key-credential managers/providers/requests plus web-auth session request and browser-session-manager traits. |
| `ASCredentialIdentityStore` | `credential_identity_store` | `CredentialIdentityStore.swift`, `ErrorDomains.swift` | ✅ | State, save/replace/remove/remove-all and listing (macOS 14.4+) call `ASCredentialIdentityStore`. Passkey identities need macOS 14, one-time-code identities macOS 15, service identifiers and display names macOS 26.2. Mutations need an app with an enabled AutoFill credential provider extension. |
| Account request family (`ASAccount*`) | `account` | `Account.swift` | ⚠️ macOS placeholder | No standalone `ASAccount` API is exposed by the macOS SDK used for this crate; placeholder APIs return a consistent `NotSupported` error. |
| `ASAccountAuthenticationModificationController` | `account_authentication_modification_controller` | `AccountAuthenticationModificationController.swift` | ⚠️ macOS placeholder | Not exposed by the macOS SDK; wrapper is documented and returns `NotSupported`. |
| `ASSettingsHelper` | `settings_helper` | `SettingsHelper.swift` | ✅ | Support probing plus bridged helper entry points, with newer methods gated by OS availability. |

## Test and example coverage

- Examples: `examples/01_authenticationservices_smoke.rs` plus one area-focused example for each major module (`02_*` through `12_*`; `12_async_authorization_controller` needs the `async` feature).
- Tests: integration tests under `tests/` cover each major module/area, including placeholder and partial-coverage behavior.

## Known macOS limitations

- `ASAccountAuthenticationModification*` is unavailable in the macOS AuthenticationServices SDK and is intentionally represented as a placeholder API surface.
- Provider-extension / Platform SSO, single sign-on, credential-provider and web-browser types are data models only. The macOS 27 SDK Platform SSO OpenID and token-exchange additions are not covered.
- `ASCredentialIdentityStore` mutations fail with `FrameworkError` unless the app has an enabled AutoFill credential provider extension.
- Some newer APIs are OS-gated by Apple, including:
  - HTTPS callback matching for `ASWebAuthenticationSession.Callback` (macOS 14.4+)
  - WebAuthn client data (passkeys macOS 13.5+, security keys macOS 14.4+)
  - several large-blob and PRF passkey properties (macOS 14+/15+)
  - `ASSettingsHelper.requestToTurnOnCredentialProviderExtension()` (macOS 15+)
