use authenticationservices::{
    account_request_family_is_supported, account_request_family_unsupported_reason,
    CredentialServiceIdentifier, ReplacePasswordWithSignInWithAppleRequest,
    UpgradePasswordToStrongPasswordRequest,
};

fn main() {
    let service = CredentialServiceIdentifier::domain("example.com");
    let replace = ReplacePasswordWithSignInWithAppleRequest::new("alice@example.com", service.clone());
    let upgrade = UpgradePasswordToStrongPasswordRequest::new("alice@example.com", service);

    println!("account request family supported: {}", account_request_family_is_supported());
    println!("reason: {}", account_request_family_unsupported_reason());
    println!("replace request: {replace:?}");
    println!("upgrade request: {upgrade:?}");
}
