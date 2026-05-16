use authenticationservices::{
    CredentialIdentity, CredentialIdentityStore, CredentialServiceIdentifier, PasswordCredentialIdentity,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = CredentialIdentityStore::shared();
    let state = store.state()?;
    println!(
        "credential identity store: enabled={}, incremental_updates={}",
        state.is_enabled, state.supports_incremental_updates
    );

    let identity = CredentialIdentity::Password(PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "alice@example.com".into(),
        record_identifier: Some("record-1".into()),
        rank: 0,
    });
    println!("save_identities result: {:?}", store.save_identities(&[identity]));
    Ok(())
}
