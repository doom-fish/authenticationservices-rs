#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::unused_self
)]

pub mod authorization;
pub mod error;
mod ffi;
mod private;
pub mod provider;
pub mod web_auth_session;

pub use authorization::{AppleIdCredential, Authorization, AuthorizationController};
pub use error::AuthenticationServicesError;
pub use provider::{AppleIdProvider, PasswordProvider, PlatformPublicKeyCredentialProvider};
pub use web_auth_session::WebAuthenticationSession;

/// Common imports.
pub mod prelude {
    pub use crate::authorization::{AppleIdCredential, Authorization, AuthorizationController};
    pub use crate::error::AuthenticationServicesError;
    pub use crate::provider::{
        AppleIdProvider, PasswordProvider, PlatformPublicKeyCredentialProvider,
    };
    pub use crate::web_auth_session::WebAuthenticationSession;
}
