# authenticationservices-rs

Safe Rust bindings for Apple's [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) framework on macOS.

> **Status:** Sign in with Apple, password, passkey and security-key requests, `ASAuthorizationController`, `ASWebAuthenticationSession`, `ASCredentialIdentityStore` and `ASSettingsHelper` call into the framework through the Swift bridge. The provider-extension / Platform SSO, single sign-on, credential-provider and web-browser families are Rust-side data models that make no framework calls; see [`COVERAGE.md`](COVERAGE.md).

## Installation

```toml
[dependencies]
authenticationservices-rs = "0.4"
```

The library is imported as `authenticationservices`. The optional `async` feature adds executor-agnostic futures for `ASAuthorizationController` and `ASWebAuthenticationSession`.

## Requirements

- macOS 12 or newer (the Swift bridge's deployment target) and Rust 1.82 or newer.
- Newer APIs are checked at run time and return `AuthenticationServicesError::NotSupported` on older systems: `ASAuthorizationController` request options need macOS 13, `client_data` needs macOS 13.5 for passkeys and macOS 14.4 for security keys, passkey credential identities need macOS 14, listing credential identities and HTTPS web-session callbacks need macOS 14.4, the security-key `appID` needs macOS 14.5, one-time-code credential identities and the passkey `requestStyle` need macOS 15, and app service identifiers and display names on credential identities need macOS 26.2.
- Cancelling an authorization controller needs macOS 13; on macOS 12 `AuthorizationGuard::cancel` returns `NotSupported`. Large-blob inputs need macOS 14 and PRF inputs macOS 15; on older systems they are ignored and the matching outputs are `None`.

## Entitlements

- Passkey requests need an associated-domains `webcredentials:` entry for the relying party, and Sign in with Apple needs the Sign in with Apple capability.
- Performing requests created from `client_data` is meant for web browsers and needs the web-browser public-key-credential entitlement.
- Saving, replacing or removing credential identities needs an app with a credential provider extension that the user has enabled. Otherwise the framework's error is returned as `AuthenticationServicesError::FrameworkError`.

## Security and threading

- Every passkey and security-key request needs a non-empty challenge, either directly or inside `client_data`; a missing or empty one is an `InvalidArgument` error. The challenge and client data are fixed when a request is created, so create a new request for each ceremony.
- `Debug` output redacts identity tokens, authorization codes, passwords, signatures, passkey user IDs, PRF outputs and large-blob data.
- `AuthorizationGuard` and `WebAuthenticationSessionGuard` own their callback context. Dropping a guard cancels the flow, and callbacks that arrive afterwards are ignored.
- Every bridge call checks the class of the handle it is given and returns `InvalidArgument` for a mismatch.
- Request handles are `Send` but not `Sync`. `update` returns `InvalidArgument` while an authorization controller still holds the request.
- The framework runs authorization and web-authentication flows on the main thread, so the host must run its main run loop. `WebAuthenticationSession::start` waits for the main thread when it is called from another thread.

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
- `CredentialIdentityStore` and credential identity models — `ASCredentialIdentityStore` state, save/replace/remove/remove-all, and listing of password, passkey and one-time-code identities.
- `SettingsHelper` — wrappers for the `ASSettingsHelper` static helpers.
- `AppleIdButton`, `UserDetectionStatus`, `UserAgeRange`, and `authorization_*_error_domain` helpers — Apple ID UI helpers plus shared authorization metadata.
- `ProviderExtension*`, `SingleSignOn*`, `CredentialProvider*`, and `WebBrowser*` wrappers — Rust-side models for Platform SSO, SSO credentials, credential-provider/passkey extension flows, and browser-mediated passkey requests.
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
- `cargo run --example 12_async_authorization_controller --features async`

## Coverage notes

- See [`COVERAGE.md`](COVERAGE.md) for the per-area matrix.
- `ASAccountAuthenticationModification*` is not available in the macOS `AuthenticationServices` SDK, so this crate exposes explicit placeholder types that return `AuthenticationServicesError::NotSupported` on macOS.
- `ASCredentialIdentityStore` state, mutation and listing are bridged to the framework; see Requirements and Entitlements above.
- The Platform SSO `OpenID` and token-exchange additions in the macOS 27 SDK are not covered.
- Some newer `AuthenticationServices` features remain gated by macOS availability (for example HTTPS callback matching in `ASWebAuthenticationSession.Callback`, large-blob and PRF details for passkeys, and the newest `ASSettingsHelper` entry points).

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
