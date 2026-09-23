use authenticationservices::{
    AuthenticationServicesError, CredentialIdentity, CredentialIdentityStore, CredentialIdentityTypes,
    CredentialServiceIdentifier, PasskeyCredentialIdentity, PasswordCredentialIdentity,
};

fn password_identity() -> CredentialIdentity {
    CredentialIdentity::Password(PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "alice@example.com".into(),
        record_identifier: Some("record-1".into()),
        rank: 0,
    })
}

#[test]
fn credential_identity_store_mutations_reach_the_framework() {
    assert!(CredentialIdentityStore::is_supported());
    let store = CredentialIdentityStore::shared();
    let state = store.state().unwrap();

    match store.save_identities(&[password_identity()]) {
        Ok(()) => store.remove_identities(&[password_identity()]).unwrap(),
        Err(error) => {
            assert!(!state.is_enabled);
            assert!(
                matches!(error, AuthenticationServicesError::FrameworkError(_)),
                "{error:?}"
            );
            assert!(
                error.to_string().contains("ASCredentialIdentityStoreErrorDomain"),
                "{error}"
            );
        }
    }
}

#[test]
fn credential_identity_store_lists_identities_for_a_service() {
    let store = CredentialIdentityStore::shared();
    let identities = store
        .credential_identities_for_service(
            &CredentialServiceIdentifier::domain("example.com"),
            CredentialIdentityTypes::PASSWORD | CredentialIdentityTypes::PASSKEY,
        )
        .unwrap();
    if !store.state().unwrap().is_enabled {
        assert!(identities.is_empty());
    }
}

#[test]
fn passkey_identities_without_a_user_handle_are_rejected() {
    let store = CredentialIdentityStore::shared();
    let identity = CredentialIdentity::Passkey(PasskeyCredentialIdentity {
        relying_party_identifier: "example.com".into(),
        user_name: "alice".into(),
        credential_id: vec![1, 2, 3],
        user_handle: None,
        record_identifier: None,
        rank: 0,
    });
    let error = store.save_identities(&[identity]).unwrap_err();
    assert!(
        matches!(error, AuthenticationServicesError::InvalidArgument(_)),
        "{error:?}"
    );
}
