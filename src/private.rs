use core::ffi::{c_char, CStr};
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(feature = "full")]
use zeroize::Zeroizing;

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

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub unsafe fn take_wiped_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    let text = String::from_utf8_lossy(bytes).into_owned();
    wipe(unsafe { core::slice::from_raw_parts_mut(ptr.cast::<u8>(), bytes.len()) });
    unsafe { ffi::authservices_string_free(ptr) };
    text
}

#[cfg(feature = "full")]
pub unsafe fn take_secret_string(ptr: *mut c_char) -> Zeroizing<String> {
    Zeroizing::new(unsafe { take_wiped_string(ptr) })
}

#[cfg(feature = "full")]
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

#[cfg(feature = "full")]
pub fn optional_secret_eq(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(feature = "full")]
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
