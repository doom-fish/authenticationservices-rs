# AuthenticationServices coverage

## v0.2.1 matrix

| Area | Rust surface | Swift bridge | Status | Notes |
| --- | --- | --- | --- | --- |
| Core authorization / Apple ID / password / passkeys | `authorization_controller`, `authorization_apple_id_provider`, `authorization_provider`, `password_credential`, `authorization_passkey` | `Authorization.swift`, `AuthorizationAppleIDProvider.swift`, `AuthorizationProvider.swift`, `PasswordCredential.swift`, `AuthorizationPasskey.swift` | ✅ | Covers the existing controller/request/credential surfaces plus Apple ID real-user-status / age-range decoding. |
| `ASWebAuthenticationSession` | `web_authentication_session` | `WebAuthSession.swift`, `ErrorDomains.swift` | ✅ | Builder, callback matching, session inspection/start/cancel, request metadata helpers, and NSError-domain accessors. |
| Apple ID button / shared aliases / traits | `authorization_apple_id_button`, `authorization_types`, `foundation_types` | `ErrorDomains.swift` | ✅ | Covers Apple ID button helpers, shared authorization/public-key/credential traits, OpenID aliases, and ASFoundation aliases. |
| Provider extension / Platform SSO | `authorization_provider_extension` | _None_ | ✅ | Rust-side models cover authorization requests/results, login configuration, login-manager state, enums, constants, and registration-handler traits. |
| Single sign-on | `authorization_single_sign_on` | _None_ | ✅ | Covers SSO provider/request/credential helpers layered on the crate's OpenID request configuration. |
| Credential-provider / passkey extension helpers | `credential_provider` | _None_ | ✅ | Covers credential-provider request/credential/context/view-controller models, passkey extension inputs/outputs, client-data helpers, and COSE identifiers. |
| Web-browser public-key-credential helpers | `authorization_web_browser` | _None_ | ✅ | Covers browser-side public-key-credential managers/providers/requests plus web-auth session request and browser-session-manager traits. |
| `ASCredentialIdentityStore` | `credential_identity_store` | `CredentialIdentityStore.swift`, `ErrorDomains.swift` | ✅ | Store state is bridged on macOS and the full SDK symbol surface is modeled; mutation/listing helpers still return `NotSupported` on macOS. |
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
