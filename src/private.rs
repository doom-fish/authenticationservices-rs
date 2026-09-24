use core::ffi::c_char;
use core::ptr;

use crate::error::AuthenticationServicesError;
use crate::ffi;

/// Take ownership of a `*mut c_char` returned from Swift, convert to `String`, and free.
///
/// # Safety
/// `ptr` must have been allocated by `strdup` in the Swift bridge.
pub unsafe fn take_string(ptr: *mut c_char) -> String {
    doom_fish_utils::ffi_string::take_owned_cstring_c(ptr, |p| ffi::authservices_string_free(p))
        .unwrap_or_default()
}

pub const REDACTED: &str = "<redacted>";

pub fn checked<T>(
    call: impl FnOnce(*mut *mut c_char) -> T,
) -> Result<T, AuthenticationServicesError> {
    let mut error = ptr::null_mut();
    let value = call(&raw mut error);
    if error.is_null() {
        Ok(value)
    } else {
        Err(AuthenticationServicesError::InvalidArgument(unsafe { take_string(error) }))
    }
}

pub fn status_result(
    status: i32,
    error: *mut c_char,
    call: &str,
) -> Result<(), AuthenticationServicesError> {
    if status == ffi::status::OK {
        return Ok(());
    }
    let message = if error.is_null() {
        format!("{call} failed with status {status}")
    } else {
        unsafe { take_string(error) }
    };
    Err(AuthenticationServicesError::from_code(status, message))
}

#[cfg(test)]
pub fn assert_wrong_handle<T>(result: Result<T, AuthenticationServicesError>) {
    match result.err() {
        Some(AuthenticationServicesError::InvalidArgument(message)) => {
            assert!(message.contains("is not a"), "{message}");
        }
        other => panic!("expected a handle-type error, got {other:?}"),
    }
}
