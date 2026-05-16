use authenticationservices::{
    authorization_provider_protocol_name, supported_authorization_provider_kinds,
    AuthorizationProviderKind,
};

#[test]
fn authorization_provider_protocol_name_matches_sdk() {
    assert_eq!(
        authorization_provider_protocol_name().unwrap(),
        "ASAuthorizationProvider"
    );
}

#[test]
fn authorization_provider_kinds_include_all_exposed_wrappers() {
    let kinds = supported_authorization_provider_kinds().unwrap();
    assert!(kinds.contains(&AuthorizationProviderKind::AppleId));
    assert!(kinds.contains(&AuthorizationProviderKind::Password));
    assert!(kinds.contains(&AuthorizationProviderKind::PlatformPublicKeyCredential));
    assert!(kinds.contains(&AuthorizationProviderKind::SecurityKeyPublicKeyCredential));
}
