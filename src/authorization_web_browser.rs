//! Web-browser public-key-credential helpers.

use std::collections::BTreeMap;

use crate::authorization_passkey::{PlatformCredentialDescriptor, PlatformPasskeyRequestStyle};
use crate::credential_provider::PublicKeyCredentialClientData;
use crate::error::AuthenticationServicesError;
use crate::foundation_types::{LocalAuthenticationContext, PresentationAnchor};
use crate::web_authentication_session::WebAuthenticationCallback;

/// Rust trait mirroring `ASAuthorizationWebBrowserExternallyAuthenticatableRequest`.
pub trait WebBrowserExternallyAuthenticatableRequest {
    fn authenticated_context(&self) -> Option<LocalAuthenticationContext>;

    fn set_authenticated_context(&mut self, context: Option<LocalAuthenticationContext>);
}

/// `ASAuthorizationWebBrowserPublicKeyCredentialManager.AuthorizationState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebBrowserPublicKeyCredentialManagerAuthorizationState {
    Authorized,
    Denied,
    NotDetermined,
}

/// `ASAuthorizationWebBrowserPlatformPublicKeyCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserPlatformPublicKeyCredential {
    pub name: String,
    pub custom_title: Option<String>,
    pub relying_party: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub provider_name: Option<String>,
}

/// `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserPlatformPublicKeyCredentialRegistrationRequest {
    pub client_data: Option<PublicKeyCredentialClientData>,
    pub excluded_credentials: Vec<PlatformCredentialDescriptor>,
    pub should_show_hybrid_transport: bool,
    pub name: String,
    pub user_id: Vec<u8>,
    pub request_style: Option<PlatformPasskeyRequestStyle>,
    authenticated_context: Option<LocalAuthenticationContext>,
}

/// `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserPlatformPublicKeyCredentialAssertionRequest {
    pub client_data: Option<PublicKeyCredentialClientData>,
    pub should_show_hybrid_transport: bool,
    authenticated_context: Option<LocalAuthenticationContext>,
}

/// `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserPlatformPublicKeyCredentialProvider {
    relying_party_identifier: String,
}

impl WebBrowserPlatformPublicKeyCredentialProvider {
    #[must_use]
    pub fn new(relying_party_identifier: impl Into<String>) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
        }
    }

    #[must_use]
    pub fn relying_party_identifier(&self) -> &str {
        &self.relying_party_identifier
    }

    #[must_use]
    pub fn create_credential_registration_request(
        &self,
        client_data: PublicKeyCredentialClientData,
        name: impl Into<String>,
        user_id: Vec<u8>,
    ) -> WebBrowserPlatformPublicKeyCredentialRegistrationRequest {
        WebBrowserPlatformPublicKeyCredentialRegistrationRequest {
            client_data: Some(client_data),
            excluded_credentials: Vec::new(),
            should_show_hybrid_transport: false,
            name: name.into(),
            user_id,
            request_style: None,
            authenticated_context: None,
        }
    }

    #[must_use]
    pub fn create_credential_registration_request_with_style(
        &self,
        client_data: PublicKeyCredentialClientData,
        name: impl Into<String>,
        user_id: Vec<u8>,
        request_style: PlatformPasskeyRequestStyle,
    ) -> WebBrowserPlatformPublicKeyCredentialRegistrationRequest {
        let mut request = self.create_credential_registration_request(client_data, name, user_id);
        request.request_style = Some(request_style);
        request
    }

    #[must_use]
    pub const fn create_credential_assertion_request(
        &self,
        client_data: PublicKeyCredentialClientData,
    ) -> WebBrowserPlatformPublicKeyCredentialAssertionRequest {
        WebBrowserPlatformPublicKeyCredentialAssertionRequest {
            client_data: Some(client_data),
            should_show_hybrid_transport: false,
            authenticated_context: None,
        }
    }
}

/// `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest {
    pub client_data: Option<PublicKeyCredentialClientData>,
    pub display_name: String,
    pub name: String,
    pub user_id: Vec<u8>,
    authenticated_context: Option<LocalAuthenticationContext>,
}

/// `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserSecurityKeyPublicKeyCredentialAssertionRequest {
    pub client_data: Option<PublicKeyCredentialClientData>,
    authenticated_context: Option<LocalAuthenticationContext>,
}

/// `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserSecurityKeyPublicKeyCredentialProvider {
    relying_party_identifier: String,
}

impl WebBrowserSecurityKeyPublicKeyCredentialProvider {
    #[must_use]
    pub fn new(relying_party_identifier: impl Into<String>) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
        }
    }

    #[must_use]
    pub fn relying_party_identifier(&self) -> &str {
        &self.relying_party_identifier
    }

    #[must_use]
    pub fn create_credential_registration_request(
        &self,
        client_data: PublicKeyCredentialClientData,
        display_name: impl Into<String>,
        name: impl Into<String>,
        user_id: Vec<u8>,
    ) -> WebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest {
        WebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest {
            client_data: Some(client_data),
            display_name: display_name.into(),
            name: name.into(),
            user_id,
            authenticated_context: None,
        }
    }

    #[must_use]
    pub const fn create_credential_assertion_request(
        &self,
        client_data: PublicKeyCredentialClientData,
    ) -> WebBrowserSecurityKeyPublicKeyCredentialAssertionRequest {
        WebBrowserSecurityKeyPublicKeyCredentialAssertionRequest {
            client_data: Some(client_data),
            authenticated_context: None,
        }
    }
}

impl WebBrowserExternallyAuthenticatableRequest for WebBrowserPlatformPublicKeyCredentialRegistrationRequest {
    fn authenticated_context(&self) -> Option<LocalAuthenticationContext> {
        self.authenticated_context
    }

    fn set_authenticated_context(&mut self, context: Option<LocalAuthenticationContext>) {
        self.authenticated_context = context;
    }
}

impl WebBrowserExternallyAuthenticatableRequest for WebBrowserPlatformPublicKeyCredentialAssertionRequest {
    fn authenticated_context(&self) -> Option<LocalAuthenticationContext> {
        self.authenticated_context
    }

    fn set_authenticated_context(&mut self, context: Option<LocalAuthenticationContext>) {
        self.authenticated_context = context;
    }
}

impl WebBrowserExternallyAuthenticatableRequest for WebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest {
    fn authenticated_context(&self) -> Option<LocalAuthenticationContext> {
        self.authenticated_context
    }

    fn set_authenticated_context(&mut self, context: Option<LocalAuthenticationContext>) {
        self.authenticated_context = context;
    }
}

impl WebBrowserExternallyAuthenticatableRequest for WebBrowserSecurityKeyPublicKeyCredentialAssertionRequest {
    fn authenticated_context(&self) -> Option<LocalAuthenticationContext> {
        self.authenticated_context
    }

    fn set_authenticated_context(&mut self, context: Option<LocalAuthenticationContext>) {
        self.authenticated_context = context;
    }
}

/// `ASAuthorizationWebBrowserPublicKeyCredentialManager`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBrowserPublicKeyCredentialManager {
    authorization_state_for_platform_credentials:
        WebBrowserPublicKeyCredentialManagerAuthorizationState,
    platform_credentials: Vec<WebBrowserPlatformPublicKeyCredential>,
    device_configured_for_passkeys: bool,
}

impl Default for WebBrowserPublicKeyCredentialManager {
    fn default() -> Self {
        Self {
            authorization_state_for_platform_credentials:
                WebBrowserPublicKeyCredentialManagerAuthorizationState::NotDetermined,
            platform_credentials: Vec::new(),
            device_configured_for_passkeys: false,
        }
    }
}

impl WebBrowserPublicKeyCredentialManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn is_device_configured_for_passkeys(&self) -> bool {
        self.device_configured_for_passkeys
    }

    pub fn set_device_configured_for_passkeys(&mut self, configured: bool) {
        self.device_configured_for_passkeys = configured;
    }

    pub fn request_authorization_for_public_key_credentials(
        &mut self,
        authorization_state: WebBrowserPublicKeyCredentialManagerAuthorizationState,
    ) -> WebBrowserPublicKeyCredentialManagerAuthorizationState {
        self.authorization_state_for_platform_credentials = authorization_state;
        authorization_state
    }

    pub fn add_platform_credential(&mut self, credential: WebBrowserPlatformPublicKeyCredential) {
        self.platform_credentials.push(credential);
    }

    #[must_use]
    pub fn platform_credentials_for_relying_party(
        &self,
        relying_party: &str,
    ) -> Vec<WebBrowserPlatformPublicKeyCredential> {
        self.platform_credentials
            .iter()
            .filter(|credential| credential.relying_party == relying_party)
            .cloned()
            .collect()
    }

    #[must_use]
    pub const fn authorization_state_for_platform_credentials(
        &self,
    ) -> WebBrowserPublicKeyCredentialManagerAuthorizationState {
        self.authorization_state_for_platform_credentials
    }
}

/// Rust type alias mirroring `ASWebAuthenticationSessionCompletionHandler`.
pub type WebAuthenticationSessionCompletionHandler =
    Box<dyn FnMut(Option<String>, Option<AuthenticationServicesError>) + Send + 'static>;

/// Rust trait mirroring `ASWebAuthenticationPresentationContextProviding`.
pub trait WebAuthenticationPresentationContextProviding {
    fn presentation_anchor_for_web_authentication_session(&self) -> PresentationAnchor;
}

/// Rust trait mirroring `ASWebAuthenticationSessionRequestDelegate`.
pub trait WebAuthenticationSessionRequestDelegate {
    fn authentication_session_request_did_complete_with_callback_url(
        &mut self,
        authentication_session_request: &WebAuthenticationSessionRequest,
        callback_url: &str,
    );

    fn authentication_session_request_did_cancel_with_error(
        &mut self,
        authentication_session_request: &WebAuthenticationSessionRequest,
        error: &AuthenticationServicesError,
    );
}

/// `ASWebAuthenticationSessionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthenticationSessionRequest {
    pub uuid: String,
    pub url: String,
    pub callback_url_scheme: Option<String>,
    pub should_use_ephemeral_session: bool,
    pub additional_header_fields: BTreeMap<String, String>,
    pub callback: Option<WebAuthenticationCallback>,
    pub completed_callback_url: Option<String>,
    pub cancelled_error: Option<String>,
}

impl WebAuthenticationSessionRequest {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            uuid: String::new(),
            url: url.into(),
            callback_url_scheme: None,
            should_use_ephemeral_session: false,
            additional_header_fields: BTreeMap::new(),
            callback: None,
            completed_callback_url: None,
            cancelled_error: None,
        }
    }

    pub fn cancel_with_error(&mut self, error: &AuthenticationServicesError) {
        self.cancelled_error = Some(error.to_string());
    }

    pub fn complete_with_callback_url(&mut self, url: impl Into<String>) {
        self.completed_callback_url = Some(url.into());
    }
}

/// Rust trait mirroring `ASWebAuthenticationSessionWebBrowserSessionHandling`.
pub trait WebAuthenticationSessionWebBrowserSessionHandling {
    fn begin_handling_web_authentication_session_request(
        &mut self,
        request: &mut WebAuthenticationSessionRequest,
    );

    fn cancel_web_authentication_session_request(
        &mut self,
        request: &mut WebAuthenticationSessionRequest,
    );
}

/// `ASWebAuthenticationSessionWebBrowserSessionManager`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebAuthenticationSessionWebBrowserSessionManager {
    session_handler_present: bool,
    pub was_launched_by_authentication_services: bool,
}

impl WebAuthenticationSessionWebBrowserSessionManager {
    #[must_use]
    pub fn shared() -> Self {
        Self::default()
    }

    pub fn set_session_handler_present(&mut self, present: bool) {
        self.session_handler_present = present;
    }

    #[must_use]
    pub const fn session_handler_present(&self) -> bool {
        self.session_handler_present
    }
}
