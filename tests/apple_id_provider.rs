use authenticationservices::{AppleIdProvider, AppleIdRequestConfiguration, AppleIdScope};

#[test]
fn apple_id_defaults_match_framework_defaults() {
    let configuration = AppleIdRequestConfiguration::default();
    assert_eq!(
        configuration.requested_scopes,
        vec![AppleIdScope::FullName, AppleIdScope::Email]
    );
    assert!(configuration.user.is_none());
    assert!(configuration.state.is_none());
    assert!(configuration.nonce.is_none());
    assert!(configuration.requested_operation.is_none());
}

#[test]
fn apple_id_revocation_notification_name_is_available() {
    let provider = AppleIdProvider::new();
    let notification = provider.credential_revoked_notification().unwrap();
    assert!(!notification.is_empty());
    assert!(notification.contains("Credential") || notification.contains("credential"));
}
