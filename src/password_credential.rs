//! \[`ASPasswordCredential`\] helpers.

use std::ffi::CString;
use std::ptr;

use serde::Deserialize;

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

#[derive(Debug, Deserialize)]
struct PasswordCredentialPayload {
    user: String,
    password: String,
}

/// A decoded `ASPasswordCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    pub user: String,
    pub password: String,
}

impl PasswordCredential {
    /// Create and validate a password credential via `AuthenticationServices`.
    pub fn new(user: &str, password: &str) -> Result<Self, AuthenticationServicesError> {
        let user_c = CString::new(user)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let password_c = CString::new(password)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_password_credential_create(
                user_c.as_ptr(),
                password_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "password_credential_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json_ptr = unsafe { ffi::authservices_password_credential_copy_json(handle) };
        unsafe { ffi::authservices_password_credential_release(handle) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "password_credential_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: PasswordCredentialPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        Ok(Self {
            user: payload.user,
            password: payload.password,
        })
    }
}
