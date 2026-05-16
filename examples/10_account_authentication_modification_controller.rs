use authenticationservices::{
    AccountAuthenticationModificationController, CredentialServiceIdentifier,
    ReplacePasswordWithSignInWithAppleRequest,
};

fn main() {
    let controller = AccountAuthenticationModificationController::new();
    let request = ReplacePasswordWithSignInWithAppleRequest::new(
        "alice@example.com",
        CredentialServiceIdentifier::domain("example.com"),
    );
    println!(
        "controller supported: {}, perform result: {:?}",
        AccountAuthenticationModificationController::is_supported(),
        controller.perform_replace_password_with_sign_in_with_apple(&request)
    );
}
