use authenticationservices::{
    AppleIdScope, AuthorizationCredential, AuthorizationRequest, HttpResponse, QueryItem,
    SingleSignOnCredential, SingleSignOnProvider,
};

#[test]
fn single_sign_on_provider_request_and_credential_helpers_are_available() {
    let provider = SingleSignOnProvider::new("https://idp.example.com");
    assert_eq!(provider.url(), "https://idp.example.com");
    assert!(provider.can_perform_authorization());

    let mut request = provider.create_request();
    request.authorization_options = vec![QueryItem::new("prompt", Some("login".into()))];
    assert_eq!(AuthorizationRequest::provider_identifier(&request), "single_sign_on");
    assert!(request.user_interface_enabled);

    let mut credential = SingleSignOnCredential::new(vec![AppleIdScope::Email, AppleIdScope::FullName]);
    credential.state = Some("opaque-state".into());
    credential.access_token = Some(b"access-token".to_vec());
    credential.identity_token = Some(b"identity-token".to_vec());
    credential.authenticated_response = Some(
        HttpResponse::new("https://idp.example.com/callback", 200)
            .with_header("Content-Type", "application/json"),
    );
    credential.private_keys = vec!["device-key".into()];

    assert_eq!(AuthorizationCredential::provider_identifier(&credential), "single_sign_on");
    assert_eq!(credential.authorized_scopes.len(), 2);
    assert_eq!(credential.private_keys, vec!["device-key"]);
}
