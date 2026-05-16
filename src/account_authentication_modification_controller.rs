//! [`ASAccountAuthenticationModificationController`] placeholders for macOS builds.

use std::ptr;

use crate::account::{ReplacePasswordWithSignInWithAppleRequest, UpgradePasswordToStrongPasswordRequest};
use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// Placeholder controller for account-authentication-modification flows.
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountAuthenticationModificationController;

impl AccountAuthenticationModificationController {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn is_supported() -> bool {
        unsafe { ffi::authservices_account_authentication_modification_controller_is_supported() != 0 }
    }

    pub fn unsupported_reason() -> String {
        let ptr = unsafe { ffi::authservices_account_authentication_modification_controller_reason() };
        if ptr.is_null() {
            "ASAccountAuthenticationModificationController is unavailable on macOS".to_owned()
        } else {
            unsafe { private::take_string(ptr) }
        }
    }

    pub fn perform_replace_password_with_sign_in_with_apple(
        &self,
        _request: &ReplacePasswordWithSignInWithAppleRequest,
    ) -> Result<(), AuthenticationServicesError> {
        self.perform_stub()
    }

    pub fn perform_upgrade_password_to_strong_password(
        &self,
        _request: &UpgradePasswordToStrongPasswordRequest,
    ) -> Result<(), AuthenticationServicesError> {
        self.perform_stub()
    }

    fn perform_stub(&self) -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_account_authentication_modification_controller_perform_stub(
                &mut err_ptr,
            )
        };
        if status == ffi::status::OK {
            Ok(())
        } else {
            let message = if err_ptr.is_null() {
                Self::unsupported_reason()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            Err(AuthenticationServicesError::from_code(status, message))
        }
    }
}
