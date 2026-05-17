//! \[`ASSettingsHelper`\] wrappers.

use std::ptr;

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

fn status_to_result(status: i32, err_ptr: *mut *mut core::ffi::c_char) -> Result<(), AuthenticationServicesError> {
    if status == ffi::status::OK {
        Ok(())
    } else {
        let message = unsafe {
            let err_value = *err_ptr;
            if err_value.is_null() {
                format!("AuthenticationServices operation failed with status {status}")
            } else {
                private::take_string(err_value)
            }
        };
        Err(AuthenticationServicesError::from_code(status, message))
    }
}

/// Static helpers around the `ASSettingsHelper` type.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingsHelper;

impl SettingsHelper {
    /// Returns whether `ASSettingsHelper` exists on this OS version.
    #[must_use]
    pub fn is_supported() -> bool {
        unsafe { ffi::authservices_settings_helper_is_supported() != 0 }
    }

    /// Opens the credential-provider settings UI.
    pub fn open_credential_provider_app_settings() -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_settings_helper_open_credential_provider_app_settings(&mut err_ptr)
        };
        status_to_result(status, &mut err_ptr)
    }

    /// Opens the verification-code settings UI.
    pub fn open_verification_code_app_settings() -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_settings_helper_open_verification_code_app_settings(&mut err_ptr)
        };
        status_to_result(status, &mut err_ptr)
    }

    /// Requests that the system enable the credential-provider extension.
    pub fn request_to_turn_on_credential_provider_extension(
    ) -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_settings_helper_request_to_turn_on_credential_provider_extension(
                &mut err_ptr,
            )
        };
        status_to_result(status, &mut err_ptr)
    }
}
