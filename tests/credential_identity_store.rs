use std::time::{SystemTime, UNIX_EPOCH};

use authenticationservices::{
    AuthenticationServicesError, CredentialIdentity, CredentialIdentityStore,
    CredentialIdentityTypes, CredentialServiceIdentifier, PasskeyCredentialIdentity,
    PasswordCredentialIdentity,
};

struct RemoveOnDrop<'a> {
    store: &'a CredentialIdentityStore,
    identities: Option<&'a [CredentialIdentity]>,
}

impl RemoveOnDrop<'_> {
    fn disarm(mut self) {
        self.identities = None;
    }
}

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if let Some(identities) = self.identities {
            if let Err(error) = self.store.remove_identities(identities) {
                eprintln!("failed to remove the test credential identities: {error}");
            }
        }
    }
}

fn password_identity() -> CredentialIdentity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    CredentialIdentity::Password(PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "alice@example.com".into(),
        record_identifier: Some(format!(
            "dev.doomfish.authenticationservices.credential-identity-store.{}.{now}",
            std::process::id()
        )),
        rank: 0,
    })
}

#[test]
fn credential_identity_store_mutations_reach_the_framework() {
    assert!(CredentialIdentityStore::is_supported());
    let store = CredentialIdentityStore::shared();
    let state = store.state().unwrap();
    let identities = [password_identity()];

    match store.save_identities(&identities) {
        Ok(()) => {
            let saved = RemoveOnDrop {
                store: &store,
                identities: Some(&identities),
            };
            store.remove_identities(&identities).unwrap();
            saved.disarm();
        }
        Err(error) => {
            assert!(!state.is_enabled);
            assert!(
                matches!(error, AuthenticationServicesError::FrameworkError(_)),
                "{error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("ASCredentialIdentityStoreErrorDomain"),
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
        assert_eq!(
            identities,
            [] as [authenticationservices::CredentialIdentity; 0]
        );
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
