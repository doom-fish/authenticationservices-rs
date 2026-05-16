use authenticationservices::{
    account_request_family_is_supported, account_request_family_not_supported_error,
    account_request_family_unsupported_reason,
};

#[test]
fn account_request_family_is_placeholder_on_macos() {
    assert!(!account_request_family_is_supported());
    let reason = account_request_family_unsupported_reason();
    assert!(!reason.is_empty());
    assert_eq!(
        account_request_family_not_supported_error().to_string(),
        reason
    );
}
