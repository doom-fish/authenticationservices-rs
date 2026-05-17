//! Shared `AuthenticationServices` support types.

use core::ffi::c_void;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Rust stand-in for `ASPresentationAnchor` (`NSWindow *` on macOS).
pub type PresentationAnchor = *mut c_void;

/// Rust stand-in for `ASViewController` (`NSViewController` on macOS).
pub type ViewController = *mut c_void;

/// Rust stand-in for `ASImage` (`NSImage` on macOS).
pub type Image = *mut c_void;

/// Rust stand-in for `LAContext *` values used by some browser-authentication APIs.
pub type LocalAuthenticationContext = *mut c_void;

/// Simple `NSURLQueryItem` mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryItem {
    pub name: String,
    pub value: Option<String>,
}

impl QueryItem {
    #[must_use]
    pub fn new(name: impl Into<String>, value: Option<String>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Lightweight `NSHTTPURLResponse` mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
}

impl HttpResponse {
    #[must_use]
    pub fn new(url: impl Into<String>, status_code: u16) -> Self {
        Self {
            url: url.into(),
            status_code,
            headers: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}
