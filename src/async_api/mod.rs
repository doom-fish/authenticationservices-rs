//! Executor-agnostic async wrappers for callback-driven `AuthenticationServices` APIs.
//!
//! Enabled with the `async` Cargo feature.
//!
//! ## Wrapped APIs
//!
//! - [`AsyncAuthorizationController::perform_requests`] /
//!   [`AsyncAuthorizationController::perform_requests_with_options`] for
//!   `ASAuthorizationController` delegate-driven request flows, including Apple ID,
//!   password, passkey, and security-key requests.
//! - [`AsyncWebAuthenticationSession::start`] for
//!   `ASWebAuthenticationSession` completion callbacks.

#![cfg(feature = "async")]

use core::ffi::{c_char, c_void};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::future::Future;
use std::ptr;

use doom_fish_utils::completion::{AsyncCompletion, AsyncCompletionFuture};
use doom_fish_utils::panic_safe::catch_user_panic;

use crate::authorization_apple_id_provider::AppleIdRequest;
use crate::authorization_controller::{
    Authorization, AuthorizationControllerRequestOptions, AuthorizationControllerRequests,
};
use crate::authorization_passkey::{PasskeyAssertionRequest, PasskeyRegistrationRequest};
use crate::authorization_provider::PasswordRequest;
use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;
use crate::web_authentication_session::{
    create_session_handle_with_callback, WebAuthenticationSession,
};

fn flatten_async_result<T>(
    result: Result<Result<T, AuthenticationServicesError>, String>,
) -> Result<T, AuthenticationServicesError> {
    result
        .map_err(AuthenticationServicesError::Unknown)
        .and_then(|result| result)
}

unsafe extern "C" fn authorization_success_async_cb(refcon: *mut c_void, json: *mut c_char) {
    catch_user_panic(
        "authenticationservices::authorization_success_async_cb",
        || {
            let json = unsafe { private::take_string(json) };
            let result = serde_json::from_str(&json)
                .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()));
            unsafe {
                AsyncCompletion::<Result<Authorization, AuthenticationServicesError>>::complete_ok(
                    refcon, result,
                );
            };
        },
    );
}

unsafe extern "C" fn authorization_error_async_cb(
    refcon: *mut c_void,
    code: i32,
    msg: *mut c_char,
) {
    catch_user_panic(
        "authenticationservices::authorization_error_async_cb",
        || {
            let message = unsafe { private::take_string(msg) };
            let error = AuthenticationServicesError::from_code(code, message);
            unsafe {
                AsyncCompletion::<Result<Authorization, AuthenticationServicesError>>::complete_ok(
                    refcon,
                    Err(error),
                );
            };
        },
    );
}

unsafe extern "C" fn web_auth_complete_async_cb(
    refcon: *mut c_void,
    url: *mut c_char,
    code: i32,
    error_msg: *mut c_char,
) {
    catch_user_panic("authenticationservices::web_auth_complete_async_cb", || {
        let result = if code == ffi::status::OK {
            Ok(unsafe { private::take_string(url) })
        } else {
            let message = unsafe { private::take_string(error_msg) };
            Err(AuthenticationServicesError::from_code(code, message))
        };
        unsafe {
            AsyncCompletion::<Result<String, AuthenticationServicesError>>::complete_ok(
                refcon, result,
            );
        };
    });
}

/// Future returned by [`AsyncAuthorizationController`].
pub struct AuthorizationFuture {
    inner: AsyncCompletionFuture<Result<Authorization, AuthenticationServicesError>>,
    handle: *mut c_void,
}

unsafe impl Send for AuthorizationFuture {}

impl core::fmt::Debug for AuthorizationFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationFuture")
            .finish_non_exhaustive()
    }
}

impl Future for AuthorizationFuture {
    type Output = Result<Authorization, AuthenticationServicesError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(flatten_async_result)
    }
}

impl Drop for AuthorizationFuture {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                ffi::authservices_authorization_controller_cancel(self.handle);
                ffi::authservices_authorization_controller_release(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

/// Future returned by [`AsyncWebAuthenticationSession::start`].
pub struct WebAuthenticationSessionFuture {
    inner: AsyncCompletionFuture<Result<String, AuthenticationServicesError>>,
    handle: *mut c_void,
}

unsafe impl Send for WebAuthenticationSessionFuture {}

impl core::fmt::Debug for WebAuthenticationSessionFuture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebAuthenticationSessionFuture")
            .finish_non_exhaustive()
    }
}

impl Future for WebAuthenticationSessionFuture {
    type Output = Result<String, AuthenticationServicesError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(flatten_async_result)
    }
}

impl Drop for WebAuthenticationSessionFuture {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                ffi::authservices_web_auth_session_cancel(self.handle);
                ffi::authservices_web_auth_session_release(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

/// Executor-agnostic async wrapper for `ASAuthorizationController` request flows.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsyncAuthorizationController;

impl AsyncAuthorizationController {
    /// Create a new async authorization controller wrapper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Start an authorization request using the common Apple ID / password /
    /// passkey request subset.
    pub fn perform_requests(
        &self,
        apple_id: Option<&AppleIdRequest>,
        password: Option<&PasswordRequest>,
        passkey_registration: Option<&PasskeyRegistrationRequest>,
        passkey_assertion: Option<&PasskeyAssertionRequest>,
    ) -> Result<AuthorizationFuture, AuthenticationServicesError> {
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

    /// Start an authorization request and await the delegate callback result.
    pub fn perform_requests_with_options(
        &self,
        requests: AuthorizationControllerRequests<'_>,
        options: AuthorizationControllerRequestOptions,
    ) -> Result<AuthorizationFuture, AuthenticationServicesError> {
        let _ = self;
        let (inner, refcon) =
            AsyncCompletion::<Result<Authorization, AuthenticationServicesError>>::create();
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_authorization_controller_create_v2(
                requests
                    .apple_id
                    .map_or(ptr::null_mut(), |request| request.ptr),
                requests
                    .password
                    .map_or(ptr::null_mut(), |request| request.ptr),
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
                Some(authorization_success_async_cb),
                Some(authorization_error_async_cb),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "authorization_controller_create_v2 returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            unsafe {
                AsyncCompletion::<Result<Authorization, AuthenticationServicesError>>::complete_err(
                    refcon,
                    message.clone(),
                );
            };
            drop(inner);
            return Err(AuthenticationServicesError::FrameworkError(message));
        }

        let mut start_err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_authorization_controller_perform_requests_with_options(
                handle,
                options.bits(),
                &mut start_err_ptr,
            )
        };
        if status != ffi::status::OK {
            unsafe { ffi::authservices_authorization_controller_release(handle) };
            let message = if start_err_ptr.is_null() {
                format!(
                    "authorization_controller_perform_requests_with_options failed with status {status}"
                )
            } else {
                unsafe { private::take_string(start_err_ptr) }
            };
            unsafe {
                AsyncCompletion::<Result<Authorization, AuthenticationServicesError>>::complete_err(
                    refcon,
                    message.clone(),
                );
            };
            drop(inner);
            return Err(AuthenticationServicesError::from_code(status, message));
        }

        Ok(AuthorizationFuture { inner, handle })
    }
}

/// Borrowed async wrapper for `ASWebAuthenticationSession`.
#[derive(Debug, Clone, Copy)]
pub struct AsyncWebAuthenticationSession<'a> {
    session: &'a WebAuthenticationSession,
}

impl<'a> AsyncWebAuthenticationSession<'a> {
    /// Create a borrowed async wrapper around a session builder.
    #[must_use]
    pub const fn new(session: &'a WebAuthenticationSession) -> Self {
        Self { session }
    }

    /// Start the session and await its completion URL.
    pub fn start(&self) -> Result<WebAuthenticationSessionFuture, AuthenticationServicesError> {
        let (inner, refcon) =
            AsyncCompletion::<Result<String, AuthenticationServicesError>>::create();
        let handle = match create_session_handle_with_callback(
            self.session,
            refcon,
            web_auth_complete_async_cb,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                unsafe {
                    AsyncCompletion::<Result<String, AuthenticationServicesError>>::complete_err(
                        refcon,
                        error.to_string(),
                    );
                };
                drop(inner);
                return Err(error);
            }
        };

        let mut err_ptr = ptr::null_mut();
        let status = unsafe { ffi::authservices_web_auth_session_start(handle, &mut err_ptr) };
        if status != ffi::status::OK {
            unsafe { ffi::authservices_web_auth_session_release(handle) };
            let message = if err_ptr.is_null() {
                format!("web_auth_session_start failed with status {status}")
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            unsafe {
                AsyncCompletion::<Result<String, AuthenticationServicesError>>::complete_err(
                    refcon,
                    message.clone(),
                );
            };
            drop(inner);
            return Err(AuthenticationServicesError::from_code(status, message));
        }

        Ok(WebAuthenticationSessionFuture { inner, handle })
    }
}
