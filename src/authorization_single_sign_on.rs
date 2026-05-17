//! `ASAuthorizationSingleSignOn*` helpers.

use crate::authorization_apple_id_provider::{AppleIdRequestConfiguration, AppleIdScope};
use crate::authorization_types::{AuthorizationCredential, AuthorizationRequest};
use crate::foundation_types::{HttpResponse, QueryItem};

/// `ASAuthorizationSingleSignOnRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleSignOnRequest {
    pub open_id: AppleIdRequestConfiguration,
    pub authorization_options: Vec<QueryItem>,
    pub user_interface_enabled: bool,
}

impl Default for SingleSignOnRequest {
    fn default() -> Self {
        Self {
            open_id: AppleIdRequestConfiguration::default(),
            authorization_options: Vec::new(),
            user_interface_enabled: true,
        }
    }
}

/// `ASAuthorizationSingleSignOnProvider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleSignOnProvider {
    url: String,
    can_perform_authorization: bool,
}

impl SingleSignOnProvider {
    #[must_use]
    pub fn new(identity_provider_url: impl Into<String>) -> Self {
        Self {
            url: identity_provider_url.into(),
            can_perform_authorization: true,
        }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub const fn can_perform_authorization(&self) -> bool {
        self.can_perform_authorization
    }

    #[must_use]
    pub fn create_request(&self) -> SingleSignOnRequest {
        SingleSignOnRequest::default()
    }
}

/// `ASAuthorizationSingleSignOnCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleSignOnCredential {
    pub state: Option<String>,
    pub access_token: Option<Vec<u8>>,
    pub identity_token: Option<Vec<u8>>,
    pub authorized_scopes: Vec<AppleIdScope>,
    pub authenticated_response: Option<HttpResponse>,
    pub private_keys: Vec<String>,
}

impl SingleSignOnCredential {
    #[must_use]
    pub const fn new(authorized_scopes: Vec<AppleIdScope>) -> Self {
        Self {
            state: None,
            access_token: None,
            identity_token: None,
            authorized_scopes,
            authenticated_response: None,
            private_keys: Vec::new(),
        }
    }
}

impl AuthorizationRequest for SingleSignOnRequest {
    fn provider_identifier(&self) -> &'static str {
        "single_sign_on"
    }
}

impl AuthorizationCredential for SingleSignOnCredential {
    fn provider_identifier(&self) -> &'static str {
        "single_sign_on"
    }
}
