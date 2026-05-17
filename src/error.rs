use std::fmt;

use crate::ffi;
use crate::private;

/// Errors returned by the `authenticationservices` crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationServicesError {
    /// An argument was invalid.
    InvalidArgument(String),
    /// The operation timed out.
    TimedOut(String),
    /// The requested API is not supported on this platform or OS version.
    NotSupported(String),
    /// The operation was cancelled by the user.
    Cancelled(String),
    /// The underlying `AuthenticationServices` framework returned an error.
    FrameworkError(String),
    /// An error occurred that doesn't fit any other category.
    Unknown(String),
}

impl fmt::Display for AuthenticationServicesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg)
            | Self::TimedOut(msg)
            | Self::NotSupported(msg)
            | Self::Cancelled(msg)
            | Self::FrameworkError(msg)
            | Self::Unknown(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AuthenticationServicesError {}

impl AuthenticationServicesError {
    pub(crate) const fn from_code(code: i32, message: String) -> Self {
        match code {
            -1 => Self::InvalidArgument(message),
            -2 => Self::TimedOut(message),
            -3 => Self::NotSupported(message),
            -5 => Self::Cancelled(message),
            -4 => Self::FrameworkError(message),
            _ => Self::Unknown(message),
        }
    }
}

fn take_domain(
    ptr: *mut core::ffi::c_char,
    label: &str,
) -> Result<String, AuthenticationServicesError> {
    if ptr.is_null() {
        Err(AuthenticationServicesError::Unknown(format!(
            "{label} returned null"
        )))
    } else {
        Ok(unsafe { private::take_string(ptr) })
    }
}

/// Returns `ASAuthorizationErrorDomain`.
pub fn authorization_error_domain() -> Result<String, AuthenticationServicesError> {
    take_domain(
        unsafe { ffi::authservices_authorization_error_domain() },
        "authorization_error_domain",
    )
}

/// Returns `ASCredentialIdentityStoreErrorDomain`.
pub fn credential_identity_store_error_domain() -> Result<String, AuthenticationServicesError> {
    take_domain(
        unsafe { ffi::authservices_credential_identity_store_error_domain() },
        "credential_identity_store_error_domain",
    )
}

/// Returns `ASExtensionErrorDomain`.
pub fn extension_error_domain() -> Result<String, AuthenticationServicesError> {
    take_domain(
        unsafe { ffi::authservices_extension_error_domain() },
        "extension_error_domain",
    )
}

/// Returns `ASWebAuthenticationSessionErrorDomain`.
pub fn web_authentication_session_error_domain() -> Result<String, AuthenticationServicesError> {
    take_domain(
        unsafe { ffi::authservices_web_authentication_session_error_domain() },
        "web_authentication_session_error_domain",
    )
}
