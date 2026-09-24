//! \[`ASWebAuthenticationSession`\] wrappers.

use core::ffi::c_void;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::ptr;
use std::sync::{Mutex, PoisonError};

use doom_fish_utils::callback_context::CallbackContext;
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
                &raw mut err_ptr,
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

type WebSessionCell = Mutex<WebSessionState>;

unsafe extern "C" fn on_complete_trampoline(
    refcon: *mut c_void,
    url: *mut core::ffi::c_char,
    code: i32,
    error_msg: *mut core::ffi::c_char,
) {
    catch_user_panic(
        "authenticationservices::on_complete_trampoline",
        || {
            let url = unsafe { private::take_string(url) };
            let message = unsafe { private::take_string(error_msg) };
            let result = if code == ffi::status::OK {
                Ok(url)
            } else {
                Err(AuthenticationServicesError::from_code(code, message))
            };
            let store = |state: &WebSessionCell| {
                state.lock().unwrap_or_else(PoisonError::into_inner).result = Some(result);
            };
            unsafe {
                CallbackContext::<WebSessionCell>::with(
                    refcon,
                    "authenticationservices::on_complete_trampoline",
                    store,
                )
            };
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

pub(crate) fn session_payload_cstring(
    builder: &WebAuthenticationSession,
) -> Result<CString, AuthenticationServicesError> {
    let payload = session_payload_from_builder(builder);
    let payload_json = serde_json::to_string(&payload)
        .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
    CString::new(payload_json)
        .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))
}

pub(crate) fn create_session_handle_with_callback(
    payload_c: &CString,
    refcon: *mut c_void,
    release: ffi::ContextRelease,
    on_complete: unsafe extern "C" fn(
        refcon: *mut c_void,
        url: *mut core::ffi::c_char,
        code: i32,
        error_msg: *mut core::ffi::c_char,
    ),
) -> Result<*mut c_void, AuthenticationServicesError> {
    let mut err_ptr = ptr::null_mut();
    let handle = unsafe {
        ffi::authservices_web_auth_session_create_from_json(
            payload_c.as_ptr(),
            refcon,
            release,
            Some(on_complete),
            &raw mut err_ptr,
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

fn create_session_handle(
    builder: &WebAuthenticationSession,
    context: &CallbackContext<WebSessionCell>,
) -> Result<*mut c_void, AuthenticationServicesError> {
    let payload_c = session_payload_cstring(builder)?;
    create_session_handle_with_callback(
        &payload_c,
        context.retained_ptr(),
        Some(CallbackContext::<WebSessionCell>::RELEASE),
        on_complete_trampoline,
    )
}

fn inspect_handle(handle: *mut c_void) -> Result<WebAuthenticationSessionInfo, AuthenticationServicesError> {
    let json_ptr = private::checked(|error| unsafe {
        ffi::authservices_web_auth_session_copy_json(handle, error)
    })?;
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
    context: CallbackContext<WebSessionCell>,
}

unsafe impl Send for WebAuthenticationSessionGuard {}

impl Drop for WebAuthenticationSessionGuard {
    fn drop(&mut self) {
        self.context.deactivate();
        if !self.handle.is_null() {
            unsafe {
                ffi::authservices_web_auth_session_cancel(self.handle, ptr::null_mut());
                ffi::authservices_web_auth_session_release(self.handle);
            }
        }
    }
}

impl WebAuthenticationSessionGuard {
    /// Cancel the in-flight authentication session.
    pub fn cancel(&self) -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status =
            unsafe { ffi::authservices_web_auth_session_cancel(self.handle, &raw mut err_ptr) };
        private::status_result(status, err_ptr, "web_auth_session_cancel")
    }

    /// Returns the latest introspected session properties.
    pub fn info(&self) -> Result<WebAuthenticationSessionInfo, AuthenticationServicesError> {
        inspect_handle(self.handle)
    }

    /// Take the completion result if one has already been delivered.
    #[must_use]
    pub fn take_result(&self) -> Option<Result<String, AuthenticationServicesError>> {
        self.context
            .get()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .result
            .take()
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
        let context = CallbackContext::new(Mutex::new(WebSessionState { result: None }));
        let handle = create_session_handle(self, &context)?;
        let info = inspect_handle(handle);
        unsafe { ffi::authservices_web_auth_session_release(handle) };
        info
    }

    /// Start the authentication session.
    pub fn start(&self) -> Result<WebAuthenticationSessionGuard, AuthenticationServicesError> {
        let context = CallbackContext::new(Mutex::new(WebSessionState { result: None }));
        let handle = create_session_handle(self, &context)?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe { ffi::authservices_web_auth_session_start(handle, &raw mut err_ptr) };
        if status != ffi::status::OK {
            unsafe { ffi::authservices_web_auth_session_release(handle) };
            let message = if err_ptr.is_null() {
                format!("web_auth_session_start failed with status {status}")
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::from_code(status, message));
        }
        Ok(WebAuthenticationSessionGuard { handle, context })
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;
    use std::ffi::CString;
    use std::ptr;
    use std::sync::Mutex;

    use doom_fish_utils::callback_context::CallbackContext;

    use std::mem::ManuallyDrop;

    use super::{
        on_complete_trampoline, WebAuthenticationSessionGuard, WebSessionCell, WebSessionState,
    };
    use crate::authorization_apple_id_provider::AppleIdProvider;
    use crate::error::AuthenticationServicesError;
    use crate::ffi;
    use crate::private::{assert_wrong_handle, status_result};

    unsafe extern "C" {
        fn strdup(value: *const c_char) -> *mut c_char;
    }

    fn swift_string(value: &str) -> *mut c_char {
        let value = CString::new(value).expect("string");
        unsafe { strdup(value.as_ptr()) }
    }

    #[test]
    fn completions_after_the_guard_is_dropped_are_ignored() {
        let context = CallbackContext::new(Mutex::new(WebSessionState { result: None }));
        let swift_reference = context.retained_ptr();

        unsafe {
            on_complete_trampoline(
                swift_reference,
                swift_string("demo://callback?code=1"),
                ffi::status::OK,
                ptr::null_mut(),
            );
        }
        let delivered = context.get().lock().expect("state").result.take();
        assert_eq!(delivered, Some(Ok("demo://callback?code=1".to_owned())));

        drop(context);

        unsafe {
            on_complete_trampoline(
                swift_reference,
                ptr::null_mut(),
                ffi::status::CANCELLED,
                swift_string("cancelled after drop"),
            );
            (CallbackContext::<WebSessionCell>::RELEASE)(swift_reference);
        }
    }

    #[test]
    fn errors_keep_their_status() {
        let context = CallbackContext::new(Mutex::new(WebSessionState { result: None }));
        unsafe {
            on_complete_trampoline(
                context.as_ptr(),
                ptr::null_mut(),
                ffi::status::CANCELLED,
                swift_string("user cancelled"),
            );
        }
        let delivered = context.get().lock().expect("state").result.take();
        assert_eq!(
            delivered,
            Some(Err(AuthenticationServicesError::Cancelled(
                "user cancelled".to_owned()
            )))
        );
    }

    #[test]
    fn session_handles_of_another_class_are_rejected() {
        let apple_id = AppleIdProvider::new().create_request(None).expect("Apple ID request");
        let guard = ManuallyDrop::new(WebAuthenticationSessionGuard {
            handle: apple_id.ptr,
            context: CallbackContext::new(Mutex::new(WebSessionState { result: None })),
        });
        assert_wrong_handle(guard.cancel());
        assert_wrong_handle(guard.info());
        let mut err_ptr = ptr::null_mut();
        let status = unsafe { ffi::authservices_web_auth_session_start(apple_id.ptr, &raw mut err_ptr) };
        assert_wrong_handle(status_result(status, err_ptr, "web_auth_session_start"));
    }
}
