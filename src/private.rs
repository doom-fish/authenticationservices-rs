use core::ffi::c_char;
use crate::ffi;

/// Take ownership of a `*mut c_char` returned from Swift, convert to `String`, and free.
///
/// # Safety
/// `ptr` must have been allocated by `strdup` in the Swift bridge.
pub unsafe fn take_string(ptr: *mut c_char) -> String {
    doom_fish_utils::ffi_string::take_owned_cstring_c(ptr, |p| ffi::authservices_string_free(p))
        .unwrap_or_default()
}
