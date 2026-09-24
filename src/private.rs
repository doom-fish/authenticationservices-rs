use core::ffi::{c_char, CStr};
use core::ptr;

use zeroize::{Zeroize, Zeroizing};

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

pub unsafe fn take_secret_string(ptr: *mut c_char) -> Zeroizing<String> {
    if ptr.is_null() {
        return Zeroizing::new(String::new());
    }
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    let text = Zeroizing::new(String::from_utf8_lossy(bytes).into_owned());
    unsafe { core::slice::from_raw_parts_mut(ptr.cast::<u8>(), bytes.len()) }.zeroize();
    unsafe { ffi::authservices_string_free(ptr) };
    text
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            core::hint::black_box(difference | (left ^ right))
        });
    difference == 0
}

pub fn optional_secret_eq(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_eq(left, right),
        (None, None) => true,
        _ => false,
    }
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
