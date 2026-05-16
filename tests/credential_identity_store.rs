use authenticationservices::{
    AuthenticationServicesError, CredentialIdentity, CredentialIdentityStore, CredentialServiceIdentifier,
    PasswordCredentialIdentity,
};

#[test]
fn credential_identity_store_exposes_state_and_stubbed_mutation_errors() {
    let store = CredentialIdentityStore::shared();
    let state = store.state().unwrap();
    assert!(matches!(state.is_enabled, true | false));
    assert!(matches!(state.supports_incremental_updates, true | false));

    let identity = CredentialIdentity::Password(PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "alice@example.com".into(),
        record_identifier: Some("record-1".into()),
        rank: 0,
    });
    let error = store.save_identities(&[identity]).unwrap_err();
    assert!(matches!(error, AuthenticationServicesError::NotSupported(_)));
}
