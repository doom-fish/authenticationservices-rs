//! Account-request-family placeholders for macOS builds.

use serde_json::Value;

use crate::credential_identity_store::CredentialServiceIdentifier;
use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// Request to replace a password with Sign in with Apple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacePasswordWithSignInWithAppleRequest {
    pub user: String,
    pub service_identifier: CredentialServiceIdentifier,
    pub user_info: Option<Value>,
}

impl ReplacePasswordWithSignInWithAppleRequest {
    #[must_use]
    pub fn new(user: impl Into<String>, service_identifier: CredentialServiceIdentifier) -> Self {
        Self {
            user: user.into(),
            service_identifier,
            user_info: None,
        }
    }
}

/// Request to upgrade a password to a stronger system-generated password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePasswordToStrongPasswordRequest {
    pub user: String,
    pub service_identifier: CredentialServiceIdentifier,
    pub user_info: Option<Value>,
}

impl UpgradePasswordToStrongPasswordRequest {
    #[must_use]
    pub fn new(user: impl Into<String>, service_identifier: CredentialServiceIdentifier) -> Self {
        Self {
            user: user.into(),
            service_identifier,
            user_info: None,
        }
    }
}

/// Returns whether the macOS `AuthenticationServices` SDK exposes the `ASAccount*` request family.
#[must_use]
pub fn is_supported() -> bool {
    unsafe { ffi::authservices_account_request_family_is_supported() != 0 }
}

/// Returns the bridge's explanation for why the request family is unavailable.
pub fn unsupported_reason() -> String {
    let ptr = unsafe { ffi::authservices_account_request_family_reason() };
    if ptr.is_null() {
        "ASAccount request family is unavailable on macOS".to_owned()
    } else {
        unsafe { private::take_string(ptr) }
    }
}

/// Returns a consistent not-supported error for the account-request family.
pub fn not_supported_error() -> AuthenticationServicesError {
    AuthenticationServicesError::NotSupported(unsupported_reason())
}
