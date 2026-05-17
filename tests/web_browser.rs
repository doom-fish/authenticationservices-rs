use authenticationservices::{
    AuthenticationServicesError, PlatformPasskeyRequestStyle, PresentationAnchor,
    PublicKeyCredentialClientData, WebAuthenticationCallback,
    WebAuthenticationPresentationContextProviding, WebAuthenticationSessionCompletionHandler,
    WebAuthenticationSessionRequest, WebAuthenticationSessionRequestDelegate,
    WebAuthenticationSessionWebBrowserSessionHandling,
    WebAuthenticationSessionWebBrowserSessionManager,
    WebBrowserExternallyAuthenticatableRequest,
    WebBrowserPlatformPublicKeyCredential, WebBrowserPlatformPublicKeyCredentialProvider,
    WebBrowserPublicKeyCredentialManager,
    WebBrowserPublicKeyCredentialManagerAuthorizationState,
    WebBrowserSecurityKeyPublicKeyCredentialProvider,
};

struct DummyPresentationProvider;

impl WebAuthenticationPresentationContextProviding for DummyPresentationProvider {
    fn presentation_anchor_for_web_authentication_session(&self) -> PresentationAnchor {
        std::ptr::null_mut()
    }
}

struct DummyRequestDelegate;

impl WebAuthenticationSessionRequestDelegate for DummyRequestDelegate {
    fn authentication_session_request_did_complete_with_callback_url(
        &mut self,
        _authentication_session_request: &WebAuthenticationSessionRequest,
        _callback_url: &str,
    ) {
    }

    fn authentication_session_request_did_cancel_with_error(
        &mut self,
        _authentication_session_request: &WebAuthenticationSessionRequest,
        _error: &AuthenticationServicesError,
    ) {
    }
}

struct DummySessionHandler;

impl WebAuthenticationSessionWebBrowserSessionHandling for DummySessionHandler {
    fn begin_handling_web_authentication_session_request(
        &mut self,
        request: &mut WebAuthenticationSessionRequest,
    ) {
        request.complete_with_callback_url("demo://callback");
    }

    fn cancel_web_authentication_session_request(
        &mut self,
        request: &mut WebAuthenticationSessionRequest,
    ) {
        request.cancel_with_error(&AuthenticationServicesError::Cancelled("cancelled".into()));
    }
}

#[test]
fn web_browser_passkey_helpers_and_session_state_are_available() {
    let client_data = PublicKeyCredentialClientData::new(b"challenge".to_vec(), "https://example.com");

    let platform_provider = WebBrowserPlatformPublicKeyCredentialProvider::new("example.com");
    let mut platform_registration_request = platform_provider
        .create_credential_registration_request_with_style(
            client_data.clone(),
            "user@example.com",
            b"user-id".to_vec(),
            PlatformPasskeyRequestStyle::Conditional,
        );
    platform_registration_request.set_authenticated_context(Some(std::ptr::null_mut()));
    assert!(platform_registration_request.authenticated_context().is_some());

    let mut platform_assertion_request =
        platform_provider.create_credential_assertion_request(client_data.clone());
    platform_assertion_request.should_show_hybrid_transport = true;
    platform_assertion_request.set_authenticated_context(Some(std::ptr::null_mut()));
    assert!(platform_assertion_request.should_show_hybrid_transport);

    let security_key_provider = WebBrowserSecurityKeyPublicKeyCredentialProvider::new("example.com");
    let mut security_key_registration_request = security_key_provider
        .create_credential_registration_request(
            client_data.clone(),
            "Display Name",
            "user@example.com",
            b"user-id".to_vec(),
        );
    security_key_registration_request.set_authenticated_context(Some(std::ptr::null_mut()));

    let mut security_key_assertion_request =
        security_key_provider.create_credential_assertion_request(client_data);
    security_key_assertion_request.set_authenticated_context(Some(std::ptr::null_mut()));

    let credential = WebBrowserPlatformPublicKeyCredential {
        name: "user@example.com".into(),
        custom_title: Some("Example".into()),
        relying_party: "example.com".into(),
        credential_id: b"credential-id".to_vec(),
        user_handle: b"user-handle".to_vec(),
        provider_name: Some("Demo Provider".into()),
    };

    let mut manager = WebBrowserPublicKeyCredentialManager::new();
    manager.set_device_configured_for_passkeys(true);
    manager.add_platform_credential(credential.clone());
    let state = manager.request_authorization_for_public_key_credentials(
        WebBrowserPublicKeyCredentialManagerAuthorizationState::Authorized,
    );
    assert_eq!(state, WebBrowserPublicKeyCredentialManagerAuthorizationState::Authorized);
    assert!(manager.is_device_configured_for_passkeys());
    assert_eq!(manager.platform_credentials_for_relying_party("example.com"), vec![credential]);
    assert_eq!(
        manager.authorization_state_for_platform_credentials(),
        WebBrowserPublicKeyCredentialManagerAuthorizationState::Authorized
    );

    let presentation_provider = DummyPresentationProvider;
    assert_eq!(
        presentation_provider.presentation_anchor_for_web_authentication_session(),
        std::ptr::null_mut()
    );
    let mut delegate = DummyRequestDelegate;
    let mut request = WebAuthenticationSessionRequest::new("https://example.com/login");
    request.callback_url_scheme = Some("demo".into());
    request.callback = Some(WebAuthenticationCallback::CustomScheme("demo".into()));

    let mut handler = DummySessionHandler;
    handler.begin_handling_web_authentication_session_request(&mut request);
    handler.cancel_web_authentication_session_request(&mut request);
    delegate.authentication_session_request_did_complete_with_callback_url(
        &request,
        "demo://callback",
    );
    delegate.authentication_session_request_did_cancel_with_error(
        &request,
        &AuthenticationServicesError::Cancelled("cancelled".into()),
    );
    assert_eq!(request.completed_callback_url.as_deref(), Some("demo://callback"));
    assert_eq!(request.cancelled_error.as_deref(), Some("cancelled"));

    let mut completion_handler: WebAuthenticationSessionCompletionHandler =
        Box::new(|_url, _error| {});
    completion_handler(None, None);

    let mut session_manager = WebAuthenticationSessionWebBrowserSessionManager::shared();
    session_manager.set_session_handler_present(true);
    assert!(session_manager.session_handler_present());
    assert!(!session_manager.was_launched_by_authentication_services);

    assert!(matches!(
        WebBrowserPublicKeyCredentialManagerAuthorizationState::Denied,
        WebBrowserPublicKeyCredentialManagerAuthorizationState::Denied
    ));
    assert!(matches!(
        WebBrowserPublicKeyCredentialManagerAuthorizationState::NotDetermined,
        WebBrowserPublicKeyCredentialManagerAuthorizationState::NotDetermined
    ));
}
