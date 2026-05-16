use authenticationservices::{
    AccountAuthenticationModificationController, AuthenticationServicesError, CredentialServiceIdentifier,
    ReplacePasswordWithSignInWithAppleRequest,
};

#[test]
fn account_authentication_modification_controller_returns_not_supported() {
    let controller = AccountAuthenticationModificationController::new();
    assert!(!AccountAuthenticationModificationController::is_supported());
    let request = ReplacePasswordWithSignInWithAppleRequest::new(
        "alice@example.com",
        CredentialServiceIdentifier::domain("example.com"),
    );
    let error = controller
        .perform_replace_password_with_sign_in_with_apple(&request)
        .unwrap_err();
    assert!(matches!(error, AuthenticationServicesError::NotSupported(_)));
}
