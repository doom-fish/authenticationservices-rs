//! \[`ASAuthorizationController`\] and decoded authorization results.

use core::ffi::c_void;
use std::fmt;
use std::ops::{BitOr, BitOrAssign};
use std::ptr;
use std::sync::{Mutex, PoisonError};

use serde::Deserialize;

use doom_fish_utils::callback_context::CallbackContext;
use doom_fish_utils::panic_safe::catch_user_panic;

use crate::authorization_apple_id_provider::AppleIdRequest;
use crate::authorization_types::{UserAgeRange, UserDetectionStatus};
use crate::authorization_passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, PlatformPublicKeyCredentialAssertion,
    PlatformPublicKeyCredentialRegistration, SecurityKeyAssertionRequest,
    SecurityKeyPublicKeyCredentialAssertion, SecurityKeyPublicKeyCredentialRegistration,
    SecurityKeyRegistrationRequest,
};
use crate::authorization_provider::PasswordRequest;
use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::password_credential::PasswordCredential;
use crate::private;

/// Decoded Apple ID credential.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct AppleIdCredential {
    #[serde(rename = "userIdentifier")]
    pub user_identifier: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    #[serde(rename = "identityToken")]
    pub identity_token: Option<String>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
    #[serde(rename = "realUserStatus")]
    pub real_user_status: Option<UserDetectionStatus>,
    #[serde(rename = "userAgeRange")]
    pub user_age_range: Option<UserAgeRange>,
}

/// Generic authorization result from any provider.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct Authorization {
    pub provider: String,
    #[serde(rename = "userIdentifier")]
    pub user_identifier: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    #[serde(rename = "identityToken")]
    pub identity_token: Option<String>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
    #[serde(rename = "realUserStatus")]
    pub real_user_status: Option<UserDetectionStatus>,
    #[serde(rename = "userAgeRange")]
    pub user_age_range: Option<UserAgeRange>,
    pub password: Option<String>,
    #[serde(rename = "credentialID")]
    pub credential_id: Option<String>,
    #[serde(rename = "rawAttestationObject")]
    pub raw_attestation_object: Option<String>,
    #[serde(rename = "rawAuthenticatorData")]
    pub raw_authenticator_data: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "userID")]
    pub user_id: Option<String>,
    pub attachment: Option<i32>,
    #[serde(rename = "usedAppID")]
    pub used_app_id: Option<bool>,
    pub transports: Option<Vec<String>>,
    #[serde(rename = "largeBlobResultKind")]
    pub large_blob_result_kind: Option<String>,
    #[serde(rename = "largeBlobData")]
    pub large_blob_data: Option<String>,
    #[serde(rename = "largeBlobWriteSucceeded")]
    pub large_blob_write_succeeded: Option<bool>,
    #[serde(rename = "largeBlobSupported")]
    pub large_blob_supported: Option<bool>,
    #[serde(rename = "prfFirst")]
    pub prf_first: Option<String>,
    #[serde(rename = "prfSecond")]
    pub prf_second: Option<String>,
    #[serde(rename = "prfSupported")]
    pub prf_supported: Option<bool>,
}

impl fmt::Debug for AppleIdCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleIdCredential")
            .field("user_identifier", &self.user_identifier)
            .field("email", &self.email)
            .field("full_name", &self.full_name)
            .field("identity_token", &self.identity_token.as_ref().map(|_| private::REDACTED))
            .field("authorization_code", &self.authorization_code.as_ref().map(|_| private::REDACTED))
            .field("real_user_status", &self.real_user_status)
            .field("user_age_range", &self.user_age_range)
            .finish()
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("provider", &self.provider)
            .field("user_identifier", &self.user_identifier)
            .field("email", &self.email)
            .field("full_name", &self.full_name)
            .field("identity_token", &self.identity_token.as_ref().map(|_| private::REDACTED))
            .field("authorization_code", &self.authorization_code.as_ref().map(|_| private::REDACTED))
            .field("real_user_status", &self.real_user_status)
            .field("user_age_range", &self.user_age_range)
            .field("password", &self.password.as_ref().map(|_| private::REDACTED))
            .field("credential_id", &self.credential_id)
            .field("raw_attestation_object", &self.raw_attestation_object)
            .field("raw_authenticator_data", &self.raw_authenticator_data)
            .field("signature", &self.signature.as_ref().map(|_| private::REDACTED))
            .field("user_id", &self.user_id.as_ref().map(|_| private::REDACTED))
            .field("attachment", &self.attachment)
            .field("used_app_id", &self.used_app_id)
            .field("transports", &self.transports)
            .field("large_blob_result_kind", &self.large_blob_result_kind)
            .field("large_blob_data", &self.large_blob_data.as_ref().map(|_| private::REDACTED))
            .field("large_blob_write_succeeded", &self.large_blob_write_succeeded)
            .field("large_blob_supported", &self.large_blob_supported)
            .field("prf_first", &self.prf_first.as_ref().map(|_| private::REDACTED))
            .field("prf_second", &self.prf_second.as_ref().map(|_| private::REDACTED))
            .field("prf_supported", &self.prf_supported)
            .finish()
    }
}

impl Authorization {
    #[must_use]
    pub fn apple_id_credential(&self) -> Option<AppleIdCredential> {
        (self.provider == "apple_id").then(|| AppleIdCredential {
            user_identifier: self.user_identifier.clone(),
            email: self.email.clone(),
            full_name: self.full_name.clone(),
            identity_token: self.identity_token.clone(),
            authorization_code: self.authorization_code.clone(),
            real_user_status: self.real_user_status,
            user_age_range: self.user_age_range,
        })
    }

    #[must_use]
    pub fn password_credential(&self) -> Option<PasswordCredential> {
        if self.provider == "password" {
            Some(PasswordCredential {
                user: self.user_identifier.clone().unwrap_or_default(),
                password: self.password.clone().unwrap_or_default(),
            })
        } else {
            None
        }
    }

    pub fn platform_passkey_registration_credential(
        &self,
    ) -> Result<Option<PlatformPublicKeyCredentialRegistration>, AuthenticationServicesError> {
        if self.provider != "platform_passkey_registration" {
            return Ok(None);
        }
        PlatformPublicKeyCredentialRegistration::from_authorization(
            self.credential_id.clone(),
            self.raw_attestation_object.clone(),
            self.attachment,
            self.large_blob_supported,
            self.prf_first.clone(),
            self.prf_second.clone(),
            self.prf_supported,
        )
    }

    pub fn platform_passkey_assertion_credential(
        &self,
    ) -> Result<Option<PlatformPublicKeyCredentialAssertion>, AuthenticationServicesError> {
        if self.provider != "platform_passkey_assertion" {
            return Ok(None);
        }
        PlatformPublicKeyCredentialAssertion::from_authorization(
            self.credential_id.clone(),
            self.raw_authenticator_data.clone(),
            self.signature.clone(),
            self.user_id.clone(),
            self.attachment,
            self.large_blob_result_kind.clone(),
            self.large_blob_data.clone(),
            self.large_blob_write_succeeded,
            self.prf_first.clone(),
            self.prf_second.clone(),
        )
    }

    pub fn security_key_registration_credential(
        &self,
    ) -> Result<Option<SecurityKeyPublicKeyCredentialRegistration>, AuthenticationServicesError> {
        if self.provider != "security_key_passkey_registration" {
            return Ok(None);
        }
        SecurityKeyPublicKeyCredentialRegistration::from_authorization(
            self.credential_id.clone(),
            self.raw_attestation_object.clone(),
            self.transports.clone(),
        )
    }

    pub fn security_key_assertion_credential(
        &self,
    ) -> Result<Option<SecurityKeyPublicKeyCredentialAssertion>, AuthenticationServicesError> {
        if self.provider != "security_key_passkey_assertion" {
            return Ok(None);
        }
        SecurityKeyPublicKeyCredentialAssertion::from_authorization(
            self.credential_id.clone(),
            self.raw_authenticator_data.clone(),
            self.signature.clone(),
            self.user_id.clone(),
            self.used_app_id,
        )
    }
}

struct CallbackState {
    result: Option<Result<Authorization, AuthenticationServicesError>>,
}

type AuthorizationCell = Mutex<CallbackState>;

fn store_result(refcon: *mut c_void, result: Result<Authorization, AuthenticationServicesError>) {
    let store = |state: &AuthorizationCell| {
        state.lock().unwrap_or_else(PoisonError::into_inner).result = Some(result);
    };
    unsafe {
        CallbackContext::<AuthorizationCell>::with(
            refcon,
            "authenticationservices::authorization_result",
            store,
        )
    };
}

/// `ASAuthorizationController.RequestOptions` bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthorizationControllerRequestOptions(u64);

impl AuthorizationControllerRequestOptions {
    pub const PREFER_IMMEDIATELY_AVAILABLE_CREDENTIALS: Self = Self(1);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for AuthorizationControllerRequestOptions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for AuthorizationControllerRequestOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Borrowed request bundle passed into the controller.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthorizationControllerRequests<'a> {
    pub apple_id: Option<&'a AppleIdRequest>,
    pub password: Option<&'a PasswordRequest>,
    pub platform_passkey_registration: Option<&'a PasskeyRegistrationRequest>,
    pub platform_passkey_assertion: Option<&'a PasskeyAssertionRequest>,
    pub security_key_registration: Option<&'a SecurityKeyRegistrationRequest>,
    pub security_key_assertion: Option<&'a SecurityKeyAssertionRequest>,
}

/// Guard that keeps the `ASAuthorizationController` alive and receives delegate callbacks.
pub struct AuthorizationGuard {
    handle: *mut c_void,
    context: CallbackContext<AuthorizationCell>,
}

unsafe impl Send for AuthorizationGuard {}

impl Drop for AuthorizationGuard {
    fn drop(&mut self) {
        self.context.deactivate();
        if !self.handle.is_null() {
            unsafe {
                ffi::authservices_authorization_controller_cancel(self.handle);
                ffi::authservices_authorization_controller_release(self.handle);
            }
        }
    }
}

impl AuthorizationGuard {
    /// Instruct the controller to cancel any in-flight request UI.
    pub fn cancel(&self) {
        unsafe { ffi::authservices_authorization_controller_cancel(self.handle) };
    }

    /// Returns the number of request objects held by the controller.
    #[must_use]
    pub fn request_count(&self) -> usize {
        let count = unsafe { ffi::authservices_authorization_controller_request_count(self.handle) };
        usize::try_from(count).unwrap_or(usize::MAX)
    }

    /// Take the result if the asynchronous callback has already delivered one.
    #[must_use]
    pub fn take_result(&self) -> Option<Result<Authorization, AuthenticationServicesError>> {
        self.context
            .get()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .result
            .take()
    }
}

unsafe extern "C" fn on_success_trampoline(refcon: *mut c_void, json: *mut core::ffi::c_char) {
    catch_user_panic(
        "authenticationservices::on_success_trampoline",
        || {
            let json = unsafe { private::take_string(json) };
            let result = serde_json::from_str(&json)
                .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()));
            store_result(refcon, result);
        },
    );
}

unsafe extern "C" fn on_error_trampoline(
    refcon: *mut c_void,
    code: i32,
    msg: *mut core::ffi::c_char,
) {
    catch_user_panic(
        "authenticationservices::on_error_trampoline",
        || {
            let message = unsafe { private::take_string(msg) };
            store_result(refcon, Err(AuthenticationServicesError::from_code(code, message)));
        },
    );
}

/// Zero-sized controller builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthorizationController;

impl AuthorizationController {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn perform_requests(
        &self,
        apple_id: Option<&AppleIdRequest>,
        password: Option<&PasswordRequest>,
        passkey_registration: Option<&PasskeyRegistrationRequest>,
        passkey_assertion: Option<&PasskeyAssertionRequest>,
    ) -> Result<AuthorizationGuard, AuthenticationServicesError> {
        self.perform_requests_with_options(
            AuthorizationControllerRequests {
                apple_id,
                password,
                platform_passkey_registration: passkey_registration,
                platform_passkey_assertion: passkey_assertion,
                security_key_registration: None,
                security_key_assertion: None,
            },
            AuthorizationControllerRequestOptions::empty(),
        )
    }

    pub fn perform_requests_with_options(
        &self,
        requests: AuthorizationControllerRequests<'_>,
        options: AuthorizationControllerRequestOptions,
    ) -> Result<AuthorizationGuard, AuthenticationServicesError> {
        let context = CallbackContext::new(Mutex::new(CallbackState { result: None }));
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_authorization_controller_create_v2(
                requests.apple_id.map_or(ptr::null_mut(), |request| request.ptr),
                requests.password.map_or(ptr::null_mut(), |request| request.ptr),
                requests
                    .platform_passkey_registration
                    .map_or(ptr::null_mut(), |request| request.ptr),
                requests
                    .platform_passkey_assertion
                    .map_or(ptr::null_mut(), |request| request.ptr),
                requests
                    .security_key_registration
                    .map_or(ptr::null_mut(), |request| request.ptr),
                requests
                    .security_key_assertion
                    .map_or(ptr::null_mut(), |request| request.ptr),
                context.retained_ptr(),
                Some(CallbackContext::<AuthorizationCell>::RELEASE),
                Some(on_success_trampoline),
                Some(on_error_trampoline),
                &raw mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "authorization_controller_create_v2 returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let guard = AuthorizationGuard { handle, context };
        let mut start_err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_authorization_controller_perform_requests_with_options(
                handle,
                options.bits(),
                &raw mut start_err_ptr,
            )
        };
        if status != ffi::status::OK {
            let message = if start_err_ptr.is_null() {
                format!("authorization_controller_perform_requests_with_options failed with status {status}")
            } else {
                unsafe { private::take_string(start_err_ptr) }
            };
            return Err(AuthenticationServicesError::from_code(status, message));
        }
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;
    use std::ffi::CString;
    use std::sync::Mutex;

    use doom_fish_utils::callback_context::CallbackContext;

    use super::{on_error_trampoline, on_success_trampoline, AuthorizationCell, CallbackState};
    use crate::authorization_apple_id_provider::{AppleIdProvider, AppleIdRequestConfiguration, AppleIdScope};
    use crate::authorization_passkey::{
        PlatformPasskeyAssertionOptions, PlatformPublicKeyCredentialProvider,
        PublicKeyCredentialUserVerificationPreference, SecurityKeyAssertionOptions,
        SecurityKeyPublicKeyCredentialProvider,
    };
    use crate::error::AuthenticationServicesError;
    use crate::ffi;

    unsafe extern "C" {
        fn strdup(value: *const c_char) -> *mut c_char;
    }

    fn swift_string(value: &str) -> *mut c_char {
        let value = CString::new(value).expect("string");
        unsafe { strdup(value.as_ptr()) }
    }

    #[test]
    fn delegate_results_after_the_guard_is_dropped_are_ignored() {
        let context = CallbackContext::new(Mutex::new(CallbackState { result: None }));
        let swift_reference = context.retained_ptr();

        unsafe {
            on_success_trampoline(
                swift_reference,
                swift_string(r#"{"provider":"password","userIdentifier":"alice","password":"pw"}"#),
            );
        }
        let delivered = context.get().lock().expect("state").result.take();
        let authorization = delivered.expect("result").expect("authorization");
        assert_eq!(authorization.provider, "password");
        assert_eq!(authorization.user_identifier.as_deref(), Some("alice"));

        drop(context);

        unsafe {
            on_error_trampoline(
                swift_reference,
                ffi::status::CANCELLED,
                swift_string("cancelled after drop"),
            );
            on_success_trampoline(swift_reference, swift_string("{}"));
            (CallbackContext::<AuthorizationCell>::RELEASE)(swift_reference);
        }
    }

    #[test]
    fn delegate_errors_keep_their_status() {
        let context = CallbackContext::new(Mutex::new(CallbackState { result: None }));
        unsafe {
            on_error_trampoline(
                context.as_ptr(),
                ffi::status::CANCELLED,
                swift_string("user cancelled"),
            );
        }
        let delivered = context.get().lock().expect("state").result.take();
        assert!(
            matches!(delivered, Some(Err(AuthenticationServicesError::Cancelled(ref message))) if message == "user cancelled"),
            "{delivered:?}"
        );
    }

    fn is_in_use_error<T: core::fmt::Debug>(result: &Result<T, AuthenticationServicesError>) -> bool {
        matches!(
            result,
            Err(AuthenticationServicesError::InvalidArgument(message))
                if message.contains("in use by an authorization controller")
        )
    }

    #[test]
    fn requests_reject_updates_while_a_controller_holds_them() {
        let apple_id = AppleIdProvider::new().create_request(None).expect("Apple ID request");
        let passkey = PlatformPublicKeyCredentialProvider::new("example.com")
            .create_assertion_request(&[7; 32])
            .expect("passkey request");
        let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com")
            .create_assertion_request_with_options(&SecurityKeyAssertionOptions {
                challenge: Some(vec![9; 32]),
                ..SecurityKeyAssertionOptions::default()
            })
            .expect("security-key request");
        let context = CallbackContext::new(Mutex::new(CallbackState { result: None }));
        let mut err_ptr = core::ptr::null_mut();
        let controller = unsafe {
            ffi::authservices_authorization_controller_create_v2(
                apple_id.ptr,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                passkey.ptr,
                core::ptr::null_mut(),
                security_key.ptr,
                context.retained_ptr(),
                Some(CallbackContext::<AuthorizationCell>::RELEASE),
                Some(on_success_trampoline),
                Some(on_error_trampoline),
                &raw mut err_ptr,
            )
        };
        assert!(!controller.is_null());

        let apple_id_configuration = AppleIdRequestConfiguration {
            requested_scopes: vec![AppleIdScope::Email],
            ..AppleIdRequestConfiguration::default()
        };
        let passkey_options = PlatformPasskeyAssertionOptions {
            user_verification_preference: Some(PublicKeyCredentialUserVerificationPreference::Required),
            ..PlatformPasskeyAssertionOptions::default()
        };
        let security_key_options = SecurityKeyAssertionOptions {
            user_verification_preference: Some(PublicKeyCredentialUserVerificationPreference::Discouraged),
            ..SecurityKeyAssertionOptions::default()
        };
        assert!(is_in_use_error(&apple_id.update(&apple_id_configuration)));
        assert!(is_in_use_error(&passkey.update(&passkey_options)));
        assert!(is_in_use_error(&security_key.update(&security_key_options)));
        assert_eq!(
            passkey.configuration().expect("configuration").user_verification_preference,
            Some(PublicKeyCredentialUserVerificationPreference::Preferred)
        );

        unsafe { ffi::authservices_authorization_controller_release(controller) };

        apple_id.update(&apple_id_configuration).expect("Apple ID update");
        passkey.update(&passkey_options).expect("passkey update");
        security_key.update(&security_key_options).expect("security-key update");
        assert_eq!(
            apple_id.configuration().expect("configuration").requested_scopes,
            vec![AppleIdScope::Email]
        );
        assert_eq!(
            passkey.configuration().expect("configuration").user_verification_preference,
            Some(PublicKeyCredentialUserVerificationPreference::Required)
        );
        assert_eq!(
            security_key.configuration().expect("configuration").user_verification_preference,
            Some(PublicKeyCredentialUserVerificationPreference::Discouraged)
        );
    }
}
