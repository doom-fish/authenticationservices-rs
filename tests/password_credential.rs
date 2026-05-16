use authenticationservices::PasswordCredential;

#[test]
fn password_credential_constructor_round_trips_user_and_password() {
    let credential = PasswordCredential::new("alice@example.com", "correct horse battery staple").unwrap();
    assert_eq!(credential.user, "alice@example.com");
    assert_eq!(credential.password, "correct horse battery staple");
}
