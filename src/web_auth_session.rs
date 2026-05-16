//! [`WebAuthenticationSession`] — wraps `ASWebAuthenticationSession`.

use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;
use std::sync::{Arc, Mutex};

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

struct WebSessionState {
    result: Option<Result<String, AuthenticationServicesError>>,
}

unsafe extern "C" fn on_complete_trampoline(
    refcon: *mut c_void,
    url: *mut core::ffi::c_char,
    code: i32,
    error_msg: *mut core::ffi::c_char,
) {
    let state = &*(refcon as *const Mutex<WebSessionState>);
    let result = if code == crate::ffi::status::OK {
        Ok(private::take_string(url))
    } else {
        let msg = private::take_string(error_msg);
        Err(AuthenticationServicesError::from_code(code, msg))
    };
    if let Ok(mut guard) = state.lock() {
        guard.result = Some(result);
    }
}

/// Guard keeping the underlying `ASWebAuthenticationSession` alive.
pub struct WebAuthenticationSessionGuard {
    handle: *mut c_void,
    state: Arc<Mutex<WebSessionState>>,
}

unsafe impl Send for WebAuthenticationSessionGuard {}

impl Drop for WebAuthenticationSessionGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::authservices_web_auth_session_release(self.handle) };
        }
    }
}

impl WebAuthenticationSessionGuard {
    /// Cancel the web authentication session.
    pub fn cancel(&self) {
        unsafe { ffi::authservices_web_auth_session_cancel(self.handle) };
    }

    /// Take the result if the completion handler has been called.
    #[must_use]
    pub fn take_result(&self) -> Option<Result<String, AuthenticationServicesError>> {
        self.state.lock().ok()?.result.take()
    }
}

/// Wraps `ASWebAuthenticationSession` for OAuth / custom-scheme web auth flows.
#[derive(Debug, Clone)]
pub struct WebAuthenticationSession {
    url: String,
    callback_scheme: Option<String>,
}

impl WebAuthenticationSession {
    /// Create a new session builder.
    #[must_use]
    pub fn new<U, S>(url: U, callback_scheme: Option<S>) -> Self
    where
        U: Into<String>,
        S: Into<String>,
    {
        Self {
            url: url.into(),
            callback_scheme: callback_scheme.map(Into::into),
        }
    }

    /// Start the authentication session.
    pub fn start(&self) -> Result<WebAuthenticationSessionGuard, AuthenticationServicesError> {
        let url_c = CString::new(self.url.as_str())
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let scheme_c = self
            .callback_scheme
            .as_deref()
            .map(CString::new)
            .transpose()
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let scheme_ptr = scheme_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());

        let state = Arc::new(Mutex::new(WebSessionState { result: None }));
        let state_ptr: *const Mutex<WebSessionState> = Arc::as_ptr(&state);
        let refcon = state_ptr.cast_mut().cast::<c_void>();

        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_web_auth_session_create(
                url_c.as_ptr(),
                scheme_ptr,
                refcon,
                Some(on_complete_trampoline),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let msg = if err_ptr.is_null() {
                "web_auth_session_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }

        let mut start_err_ptr = ptr::null_mut();
        let status =
            unsafe { ffi::authservices_web_auth_session_start(handle, &mut start_err_ptr) };
        if status != crate::ffi::status::OK {
            unsafe { ffi::authservices_web_auth_session_release(handle) };
            let msg = if start_err_ptr.is_null() {
                format!("session start failed (code {status})")
            } else {
                unsafe { private::take_string(start_err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }

        Ok(WebAuthenticationSessionGuard { handle, state })
    }
}
