# authenticationservices-rs

Safe Rust bindings for Apple's [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) framework on macOS.

> **Status:** v0.2.0 expands the crate to cover `ASAuthorizationController`, `ASWebAuthenticationSession`, `ASPasswordCredential`, `ASAuthorizationAppleIDProvider`, passkey/public-key-credential request families, `ASAuthorizationProvider` helpers, `ASCredentialIdentityStore` state APIs, `ASSettingsHelper`, plus explicit macOS placeholders for the unavailable account-authentication-modification family.

## Quick start

```rust,no_run
use authenticationservices::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("provider protocol: {}", authorization_provider_protocol_name()?);

    let store = CredentialIdentityStore::shared();
    println!("credential identity store supported: {}", CredentialIdentityStore::is_supported());
    println!("credential identity store state: {:?}", store.state()?);

    Ok(())
}
```

## Highlights

- `AppleIdProvider`, `AppleIdRequest`, `AppleIdRequestConfiguration` — Sign in with Apple request construction and credential-state queries.
- `PasswordProvider`, `PasswordRequest`, `PasswordCredential` — keychain-password request and credential helpers.
- `PlatformPublicKeyCredentialProvider` and `SecurityKeyPublicKeyCredentialProvider` — passkey and security-key registration/assertion request builders.
- `AuthorizationController`, `AuthorizationGuard`, `Authorization` — `ASAuthorizationController` orchestration and typed credential decoding.
- `WebAuthenticationSession`, `WebAuthenticationCallback` — `ASWebAuthenticationSession` builders and callback matching helpers.
- `CredentialIdentityStore` and credential identity models — store state plus Rust-side models for password/passkey/one-time-code identities.
- `SettingsHelper` — wrappers for the `ASSettingsHelper` static helpers.
- `account` and `AccountAuthenticationModificationController` placeholders — explicit macOS `NotSupported` coverage for APIs that are unavailable in the macOS SDK.

## Examples

- `cargo run --example 01_authenticationservices_smoke`
- `cargo run --example 02_apple_id_provider`
- `cargo run --example 03_authorization_provider`
- `cargo run --example 04_password_credential`
- `cargo run --example 05_authorization_controller_result`
- `cargo run --example 06_passkeys`
- `cargo run --example 07_web_authentication_session`
- `cargo run --example 08_credential_identity_store`
- `cargo run --example 09_account_requests`
- `cargo run --example 10_account_authentication_modification_controller`
- `cargo run --example 11_settings_helper`

## Coverage notes

- See [`COVERAGE.md`](COVERAGE.md) for the per-area matrix.
- `ASAccountAuthenticationModification*` is not available in the macOS `AuthenticationServices` SDK, so this crate exposes explicit placeholder types that return `AuthenticationServicesError::NotSupported` on macOS.
- `ASCredentialIdentityStore` state inspection is bridged on macOS; mutation/listing helpers are currently surfaced as typed Rust APIs that return a consistent `NotSupported` error until the remaining bridge work lands.
- Some newer `AuthenticationServices` features remain gated by macOS availability (for example HTTPS callback matching in `ASWebAuthenticationSession.Callback`, large-blob and PRF details for passkeys, and the newest `ASSettingsHelper` entry points).

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
