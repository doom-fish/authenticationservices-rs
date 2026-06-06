//! \[`ASWebAuthenticationSession`\] wrappers.

use core::ffi::c_void;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::ptr;
use std::sync::{Arc, Mutex};

use doom_fish_utils::panic_safe::catch_user_panic;
use serde::{Deserialize, Serialize};

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WebAuthenticationCallbackPayload {
    kind: String,
    scheme: Option<String>,
    host: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WebAuthenticationSessionPayload {
    url: String,
    callback: Option<WebAuthenticationCallbackPayload>,
    #[serde(rename = "prefersEphemeralWebBrowserSession")]
    prefers_ephemeral_web_browser_session: bool,
    #[serde(rename = "additionalHeaderFields")]
    additional_header_fields: Option<BTreeMap<String, String>>,
    #[serde(rename = "canStart")]
    can_start: bool,
    #[serde(rename = "usesPresentationContextProvider")]
    uses_presentation_context_provider: bool,
}

/// `ASWebAuthenticationSession.Callback`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthenticationCallback {
    CustomScheme(String),
    Https { host: String, path: Option<String> },
}

impl WebAuthenticationCallback {
    fn to_payload(&self) -> WebAuthenticationCallbackPayload {
        match self {
            Self::CustomScheme(scheme) => WebAuthenticationCallbackPayload {
                kind: "custom_scheme".into(),
                scheme: Some(scheme.clone()),
                host: None,
                path: None,
            },
            Self::Https { host, path } => WebAuthenticationCallbackPayload {
                kind: "https".into(),
                scheme: None,
                host: Some(host.clone()),
                path: path.clone(),
            },
        }
    }

    fn from_payload(payload: WebAuthenticationCallbackPayload) -> Self {
        match payload.kind.as_str() {
            "https" => Self::Https {
                host: payload.host.unwrap_or_default(),
                path: payload.path,
            },
            _ => Self::CustomScheme(payload.scheme.unwrap_or_default()),
        }
    }

    /// Returns whether the callback matches the given URL.
    pub fn matches_url(&self, url: &str) -> Result<bool, AuthenticationServicesError> {
        let payload = serde_json::to_string(&self.to_payload())
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let payload_c = CString::new(payload)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let url_c = CString::new(url)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let result = unsafe {
            ffi::authservices_web_auth_callback_matches_url(
                payload_c.as_ptr(),
                url_c.as_ptr(),
                &mut err_ptr,
            )
        };
        match result {
            0 => Ok(false),
            1 => Ok(true),
            other => {
                let message = if err_ptr.is_null() {
                    format!("web_auth_callback_matches_url failed with status {other}")
                } else {
                    unsafe { private::take_string(err_ptr) }
                };
                Err(AuthenticationServicesError::FrameworkError(message))
            }
        }
    }
}

/// Introspected session properties from the underlying Cocoa object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthenticationSessionInfo {
    pub url: String,
    pub callback: Option<WebAuthenticationCallback>,
    pub prefers_ephemeral_web_browser_session: bool,
    pub additional_header_fields: BTreeMap<String, String>,
    pub can_start: bool,
    pub uses_presentation_context_provider: bool,
}

impl WebAuthenticationSessionInfo {
    fn from_payload(payload: WebAuthenticationSessionPayload) -> Self {
        Self {
            url: payload.url,
            callback: payload.callback.map(WebAuthenticationCallback::from_payload),
            prefers_ephemeral_web_browser_session: payload.prefers_ephemeral_web_browser_session,
            additional_header_fields: payload.additional_header_fields.unwrap_or_default(),
            can_start: payload.can_start,
            uses_presentation_context_provider: payload.uses_presentation_context_provider,
        }
    }
}

struct WebSessionState {
    result: Option<Result<String, AuthenticationServicesError>>,
}

unsafe extern "C" fn on_complete_trampoline(
    refcon: *mut c_void,
    url: *mut core::ffi::c_char,
    code: i32,
    error_msg: *mut core::ffi::c_char,
) {
    catch_user_panic(
        "authenticationservices::on_complete_trampoline",
        || {
            let state = unsafe { &*(refcon as *const Mutex<WebSessionState>) };
            let result = if code == ffi::status::OK {
                Ok(unsafe { private::take_string(url) })
            } else {
                let message = unsafe { private::take_string(error_msg) };
                Err(AuthenticationServicesError::from_code(code, message))
            };
            if let Ok(mut state) = state.lock() {
                state.result = Some(result);
            }
        },
    );
}

fn session_payload_from_builder(builder: &WebAuthenticationSession) -> WebAuthenticationSessionPayload {
    WebAuthenticationSessionPayload {
        url: builder.url.clone(),
        callback: builder.callback.as_ref().map(WebAuthenticationCallback::to_payload),
        prefers_ephemeral_web_browser_session: builder.prefers_ephemeral_web_browser_session,
        additional_header_fields: (!builder.additional_header_fields.is_empty())
            .then(|| builder.additional_header_fields.clone()),
        can_start: false,
        uses_presentation_context_provider: true,
    }
}

pub(crate) fn create_session_handle_with_callback(
    builder: &WebAuthenticationSession,
    refcon: *mut c_void,
    on_complete: unsafe extern "C" fn(
        refcon: *mut c_void,
        url: *mut core::ffi::c_char,
        code: i32,
        error_msg: *mut core::ffi::c_char,
    ),
) -> Result<*mut c_void, AuthenticationServicesError> {
    let payload = session_payload_from_builder(builder);
    let payload_json = serde_json::to_string(&payload)
        .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
    let payload_c = CString::new(payload_json)
        .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
    let mut err_ptr = ptr::null_mut();
    let handle = unsafe {
        ffi::authservices_web_auth_session_create_from_json(
            payload_c.as_ptr(),
            refcon,
            Some(on_complete),
            &mut err_ptr,
        )
    };
    if handle.is_null() {
        let message = if err_ptr.is_null() {
            "web_auth_session_create_from_json returned null".to_owned()
        } else {
            unsafe { private::take_string(err_ptr) }
        };
        return Err(AuthenticationServicesError::FrameworkError(message));
    }
    Ok(handle)
}

pub(crate) fn create_session_handle(
    builder: &WebAuthenticationSession,
    refcon: *mut c_void,
) -> Result<*mut c_void, AuthenticationServicesError> {
    create_session_handle_with_callback(builder, refcon, on_complete_trampoline)
}

fn inspect_handle(handle: *mut c_void) -> Result<WebAuthenticationSessionInfo, AuthenticationServicesError> {
    let json_ptr = unsafe { ffi::authservices_web_auth_session_copy_json(handle) };
    if json_ptr.is_null() {
        return Err(AuthenticationServicesError::Unknown(
            "web_auth_session_copy_json returned null".into(),
        ));
    }
    let json = unsafe { private::take_string(json_ptr) };
    let payload: WebAuthenticationSessionPayload =
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
    Ok(WebAuthenticationSessionInfo::from_payload(payload))
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
    /// Cancel the in-flight authentication session.
    pub fn cancel(&self) {
        unsafe { ffi::authservices_web_auth_session_cancel(self.handle) };
    }

    /// Returns the latest introspected session properties.
    pub fn info(&self) -> Result<WebAuthenticationSessionInfo, AuthenticationServicesError> {
        inspect_handle(self.handle)
    }

    /// Take the completion result if one has already been delivered.
    #[must_use]
    pub fn take_result(&self) -> Option<Result<String, AuthenticationServicesError>> {
        self.state.lock().ok()?.result.take()
    }
}

/// Builder-style wrapper around `ASWebAuthenticationSession`.
#[derive(Debug, Clone)]
pub struct WebAuthenticationSession {
    url: String,
    callback: Option<WebAuthenticationCallback>,
    prefers_ephemeral_web_browser_session: bool,
    additional_header_fields: BTreeMap<String, String>,
}

impl WebAuthenticationSession {
    /// Create a new session builder using the traditional custom-scheme callback form.
    #[must_use]
    pub fn new<U, S>(url: U, callback_scheme: Option<S>) -> Self
    where
        U: Into<String>,
        S: Into<String>,
    {
        Self {
            url: url.into(),
            callback: callback_scheme.map(|scheme| WebAuthenticationCallback::CustomScheme(scheme.into())),
            prefers_ephemeral_web_browser_session: false,
            additional_header_fields: BTreeMap::new(),
        }
    }

    /// Replace the callback descriptor.
    #[must_use]
    pub fn with_callback(mut self, callback: WebAuthenticationCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Toggle ephemeral browser mode.
    #[must_use]
    pub const fn with_prefers_ephemeral_web_browser_session(mut self, prefers_ephemeral: bool) -> Self {
        self.prefers_ephemeral_web_browser_session = prefers_ephemeral;
        self
    }

    /// Adds or replaces an HTTP header sent with the authentication session request.
    #[must_use]
    pub fn with_additional_header_field(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.additional_header_fields.insert(key.into(), value.into());
        self
    }

    /// Builds the underlying Cocoa object and returns its observable properties without starting it.
    pub fn inspect(&self) -> Result<WebAuthenticationSessionInfo, AuthenticationServicesError> {
        let state = Arc::new(Mutex::new(WebSessionState { result: None }));
        let state_ptr: *const Mutex<WebSessionState> = Arc::as_ptr(&state);
        let refcon = state_ptr.cast_mut().cast::<c_void>();
        let handle = create_session_handle(self, refcon)?;
        let info = inspect_handle(handle);
        unsafe { ffi::authservices_web_auth_session_release(handle) };
        info
    }

    /// Start the authentication session.
    pub fn start(&self) -> Result<WebAuthenticationSessionGuard, AuthenticationServicesError> {
        let state = Arc::new(Mutex::new(WebSessionState { result: None }));
        let state_ptr: *const Mutex<WebSessionState> = Arc::as_ptr(&state);
        let refcon = state_ptr.cast_mut().cast::<c_void>();
        let handle = create_session_handle(self, refcon)?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe { ffi::authservices_web_auth_session_start(handle, &mut err_ptr) };
        if status != ffi::status::OK {
            unsafe { ffi::authservices_web_auth_session_release(handle) };
            let message = if err_ptr.is_null() {
                format!("web_auth_session_start failed with status {status}")
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::from_code(status, message));
        }
        Ok(WebAuthenticationSessionGuard { handle, state })
    }
}
