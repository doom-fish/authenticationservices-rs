#![allow(missing_docs)]

use core::ffi::{c_char, c_void};

unsafe extern "C" {
    pub fn authservices_string_free(s: *mut c_char);

    pub fn authservices_apple_id_provider_create_request(
        scopes_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_apple_id_request_release(ptr: *mut c_void);
    pub fn authservices_apple_id_request_kind_json(ptr: *mut c_void) -> *mut c_char;

    pub fn authservices_password_provider_create_request(
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_password_request_release(ptr: *mut c_void);
    pub fn authservices_password_request_kind_json(ptr: *mut c_void) -> *mut c_char;

    pub fn authservices_passkey_registration_request_create(
        relying_party_id: *const c_char,
        challenge_b64: *const c_char,
        user_id_b64: *const c_char,
        user_name: *const c_char,
        user_display_name: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_passkey_registration_request_release(ptr: *mut c_void);
    pub fn authservices_passkey_registration_request_kind_json(ptr: *mut c_void) -> *mut c_char;

    pub fn authservices_passkey_assertion_request_create(
        relying_party_id: *const c_char,
        challenge_b64: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_passkey_assertion_request_release(ptr: *mut c_void);
    pub fn authservices_passkey_assertion_request_kind_json(ptr: *mut c_void) -> *mut c_char;

    pub fn authservices_authorization_controller_create(
        apple_id_request: *mut c_void,
        password_request: *mut c_void,
        passkey_reg_request: *mut c_void,
        passkey_assert_request: *mut c_void,
        refcon: *mut c_void,
        on_success: Option<unsafe extern "C" fn(refcon: *mut c_void, json: *mut c_char)>,
        on_error: Option<unsafe extern "C" fn(refcon: *mut c_void, code: i32, msg: *mut c_char)>,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_authorization_controller_perform_requests(ptr: *mut c_void);
    pub fn authservices_authorization_controller_release(ptr: *mut c_void);

    pub fn authservices_web_auth_session_create(
        url_string: *const c_char,
        callback_scheme: *const c_char,
        refcon: *mut c_void,
        on_complete: Option<
            unsafe extern "C" fn(
                refcon: *mut c_void,
                url: *mut c_char,
                code: i32,
                error_msg: *mut c_char,
            ),
        >,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_web_auth_session_start(
        ptr: *mut c_void,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_web_auth_session_cancel(ptr: *mut c_void);
    pub fn authservices_web_auth_session_release(ptr: *mut c_void);
}

#[allow(dead_code)]
pub mod status {
    pub const OK: i32 = 0;
    pub const INVALID_ARGUMENT: i32 = -1;
    pub const TIMED_OUT: i32 = -2;
    pub const NOT_SUPPORTED: i32 = -3;
    pub const FRAMEWORK_ERROR: i32 = -4;
    pub const CANCELLED: i32 = -5;
    pub const UNKNOWN: i32 = -99;
}
