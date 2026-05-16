//! [`ASAuthorizationController`] and decoded authorization results.

use core::ffi::c_void;
use std::ops::{BitOr, BitOrAssign};
use std::ptr;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::authorization_apple_id_provider::AppleIdRequest;
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
}

/// Generic authorization result from any provider.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

impl Authorization {
    #[must_use]
    pub fn apple_id_credential(&self) -> Option<AppleIdCredential> {
        (self.provider == "apple_id").then(|| AppleIdCredential {
            user_identifier: self.user_identifier.clone(),
            email: self.email.clone(),
            full_name: self.full_name.clone(),
            identity_token: self.identity_token.clone(),
            authorization_code: self.authorization_code.clone(),
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
    state: Arc<Mutex<CallbackState>>,
}

unsafe impl Send for AuthorizationGuard {}

impl Drop for AuthorizationGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::authservices_authorization_controller_release(self.handle) };
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
        self.state.lock().ok()?.result.take()
    }
}

unsafe extern "C" fn on_success_trampoline(refcon: *mut c_void, json: *mut core::ffi::c_char) {
    let state = unsafe { &*(refcon as *const Mutex<CallbackState>) };
    let json = unsafe { private::take_string(json) };
    let result = serde_json::from_str(&json)
        .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()));
    if let Ok(mut state) = state.lock() {
        state.result = Some(result);
    }
}

unsafe extern "C" fn on_error_trampoline(
    refcon: *mut c_void,
    code: i32,
    msg: *mut core::ffi::c_char,
) {
    let state = unsafe { &*(refcon as *const Mutex<CallbackState>) };
    let message = unsafe { private::take_string(msg) };
    let error = AuthenticationServicesError::from_code(code, message);
    if let Ok(mut state) = state.lock() {
        state.result = Some(Err(error));
    }
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
        let state = Arc::new(Mutex::new(CallbackState { result: None }));
        let state_ptr: *const Mutex<CallbackState> = Arc::as_ptr(&state);
        let refcon = state_ptr.cast_mut().cast::<c_void>();
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
                refcon,
                Some(on_success_trampoline),
                Some(on_error_trampoline),
                &mut err_ptr,
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
        let guard = AuthorizationGuard { handle, state };
        let mut start_err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_authorization_controller_perform_requests_with_options(
                handle,
                options.bits(),
                &mut start_err_ptr,
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
