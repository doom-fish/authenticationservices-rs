# authenticationservices-rs

Safe Rust bindings for Apple's [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) framework on macOS.

> **Status:** v0.1.0 covers Sign in with Apple, password/keychain credentials, platform passkey (WebAuthn) registration and assertion requests, and `ASWebAuthenticationSession` OAuth flows.\
> `ASAccountAuthenticationModificationController` is deferred to v0.2.

## Quick start

```rust,no_run
use authenticationservices::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = AppleIdProvider::new();
    let request = provider.create_request(Some(&["fullName", "email"]))?;
    println!("request kind: {}", request.kind()?.kind);
    Ok(())
}
```

## Highlights

- `AppleIdProvider` — builds `ASAuthorizationAppleIDRequest`s (Sign in with Apple)
- `PasswordProvider` — builds `ASAuthorizationPasswordRequest`s (keychain credentials)
- `PlatformPublicKeyCredentialProvider` — builds passkey registration + assertion requests
- `AuthorizationController` — wraps `ASAuthorizationController` with callback guard support
- `Authorization` + `AppleIdCredential` — typed result wrappers
- `WebAuthenticationSession` — wraps `ASWebAuthenticationSession` for OAuth / custom-scheme flows

## Deferred

`ASAccountAuthenticationModificationController` and its related types are deferred to v0.2.

## Smoke example

```bash
cargo run --example 01_authenticationservices_smoke
```

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
