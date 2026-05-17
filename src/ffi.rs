#![allow(dead_code, missing_docs)]

use core::ffi::{c_char, c_void};

unsafe extern "C" {
    pub fn authservices_string_free(s: *mut c_char);

    pub fn authservices_authorization_provider_protocol_name() -> *mut c_char;
    pub fn authservices_authorization_provider_supported_kinds_json() -> *mut c_char;

    pub fn authservices_authorization_error_domain() -> *mut c_char;
    pub fn authservices_credential_identity_store_error_domain() -> *mut c_char;
    pub fn authservices_extension_error_domain() -> *mut c_char;
    pub fn authservices_web_authentication_session_error_domain() -> *mut c_char;

    pub fn authservices_password_provider_create_request(
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_password_request_release(ptr: *mut c_void);
    pub fn authservices_password_request_kind_json(ptr: *mut c_void) -> *mut c_char;

    pub fn authservices_password_credential_create(
        user: *const c_char,
        password: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_password_credential_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_password_credential_release(ptr: *mut c_void);

    pub fn authservices_apple_id_provider_create_request(
        scopes_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_apple_id_request_release(ptr: *mut c_void);
    pub fn authservices_apple_id_request_kind_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_apple_id_request_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_apple_id_request_update_from_json(
        ptr: *mut c_void,
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_apple_id_provider_credential_state_json(
        user_id: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_char;
    pub fn authservices_apple_id_provider_credential_revoked_notification() -> *mut c_char;

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
    pub fn authservices_passkey_registration_request_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_passkey_registration_request_update_from_json(
        ptr: *mut c_void,
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;

    pub fn authservices_passkey_assertion_request_create(
        relying_party_id: *const c_char,
        challenge_b64: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_passkey_assertion_request_release(ptr: *mut c_void);
    pub fn authservices_passkey_assertion_request_kind_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_passkey_assertion_request_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_passkey_assertion_request_update_from_json(
        ptr: *mut c_void,
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;

    pub fn authservices_security_key_registration_request_create_from_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_security_key_registration_request_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_security_key_registration_request_update_from_json(
        ptr: *mut c_void,
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_security_key_registration_request_release(ptr: *mut c_void);

    pub fn authservices_security_key_assertion_request_create_from_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_security_key_assertion_request_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_security_key_assertion_request_update_from_json(
        ptr: *mut c_void,
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_security_key_assertion_request_release(ptr: *mut c_void);

    pub fn authservices_platform_credential_descriptor_create_from_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_platform_credential_descriptor_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_platform_credential_descriptor_release(ptr: *mut c_void);

    pub fn authservices_security_key_credential_descriptor_create_from_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_security_key_credential_descriptor_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_security_key_credential_descriptor_release(ptr: *mut c_void);

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
    pub fn authservices_authorization_controller_create_v2(
        apple_id_request: *mut c_void,
        password_request: *mut c_void,
        passkey_reg_request: *mut c_void,
        passkey_assert_request: *mut c_void,
        security_key_reg_request: *mut c_void,
        security_key_assert_request: *mut c_void,
        refcon: *mut c_void,
        on_success: Option<unsafe extern "C" fn(refcon: *mut c_void, json: *mut c_char)>,
        on_error: Option<unsafe extern "C" fn(refcon: *mut c_void, code: i32, msg: *mut c_char)>,
        out_error: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn authservices_authorization_controller_perform_requests(ptr: *mut c_void);
    pub fn authservices_authorization_controller_perform_requests_with_options(
        ptr: *mut c_void,
        raw_value: u64,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_authorization_controller_cancel(ptr: *mut c_void);
    pub fn authservices_authorization_controller_request_count(ptr: *mut c_void) -> u64;
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
    pub fn authservices_web_auth_session_create_from_json(
        payload_json: *const c_char,
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
    pub fn authservices_web_auth_session_copy_json(ptr: *mut c_void) -> *mut c_char;
    pub fn authservices_web_auth_session_start(
        ptr: *mut c_void,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_web_auth_session_cancel(ptr: *mut c_void);
    pub fn authservices_web_auth_session_release(ptr: *mut c_void);
    pub fn authservices_web_auth_callback_matches_url(
        callback_json: *const c_char,
        url_string: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;

    pub fn authservices_credential_identity_store_is_supported() -> i32;
    pub fn authservices_credential_identity_store_state_json(out_error: *mut *mut c_char) -> *mut c_char;
    pub fn authservices_credential_identity_store_save_identities_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_credential_identity_store_remove_identities_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_credential_identity_store_replace_identities_json(
        payload_json: *const c_char,
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_credential_identity_store_remove_all(
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_credential_identity_store_identities_json(
        service_payload_json: *const c_char,
        identity_types_raw_value: u64,
        out_error: *mut *mut c_char,
    ) -> *mut c_char;

    pub fn authservices_account_request_family_is_supported() -> i32;
    pub fn authservices_account_request_family_reason() -> *mut c_char;

    pub fn authservices_account_authentication_modification_controller_is_supported() -> i32;
    pub fn authservices_account_authentication_modification_controller_reason() -> *mut c_char;
    pub fn authservices_account_authentication_modification_controller_perform_stub(
        out_error: *mut *mut c_char,
    ) -> i32;

    pub fn authservices_settings_helper_is_supported() -> i32;
    pub fn authservices_settings_helper_open_credential_provider_app_settings(
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_settings_helper_open_verification_code_app_settings(
        out_error: *mut *mut c_char,
    ) -> i32;
    pub fn authservices_settings_helper_request_to_turn_on_credential_provider_extension(
        out_error: *mut *mut c_char,
    ) -> i32;
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
