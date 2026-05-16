use core::ffi::c_char;
use std::ffi::CStr;

use crate::ffi;

/// Take ownership of a `*mut c_char` returned from Swift, convert to `String`, and free.
///
/// # Safety
/// `ptr` must have been allocated by `strdup` in the Swift bridge.
pub unsafe fn take_string(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ffi::authservices_string_free(ptr);
    s
}
