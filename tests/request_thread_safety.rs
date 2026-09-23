use authenticationservices::{
    AppleIdProvider, AppleIdRequest, AppleIdRequestConfiguration, AppleIdScope, PasskeyAssertionRequest,
    PasskeyRegistrationRequest, PasswordRequest, PlatformPasskeyAssertionOptions,
    PlatformPublicKeyCredentialProvider, PublicKeyCredentialUserVerificationPreference, SecurityKeyAssertionRequest,
    SecurityKeyRegistrationRequest,
};

trait AmbiguousIfSync<Marker> {
    fn assert_not_sync() {}
}

impl<T: ?Sized> AmbiguousIfSync<()> for T {}

struct SyncMarker;

impl<T: ?Sized + Sync> AmbiguousIfSync<SyncMarker> for T {}

const fn assert_send<T: Send>() {}

#[test]
fn request_handles_can_move_between_threads_but_cannot_be_shared() {
    assert_send::<AppleIdRequest>();
    assert_send::<PasswordRequest>();
    assert_send::<PasskeyRegistrationRequest>();
    assert_send::<PasskeyAssertionRequest>();
    assert_send::<SecurityKeyRegistrationRequest>();
    assert_send::<SecurityKeyAssertionRequest>();
    <AppleIdRequest as AmbiguousIfSync<_>>::assert_not_sync();
    <PasswordRequest as AmbiguousIfSync<_>>::assert_not_sync();
    <PasskeyRegistrationRequest as AmbiguousIfSync<_>>::assert_not_sync();
    <PasskeyAssertionRequest as AmbiguousIfSync<_>>::assert_not_sync();
    <SecurityKeyRegistrationRequest as AmbiguousIfSync<_>>::assert_not_sync();
    <SecurityKeyAssertionRequest as AmbiguousIfSync<_>>::assert_not_sync();
}

#[test]
fn moved_requests_can_be_updated_on_their_new_thread() {
    let apple_id = AppleIdProvider::new().create_request(None).expect("Apple ID request");
    let passkey = PlatformPublicKeyCredentialProvider::new("example.com")
        .create_assertion_request(&[1; 32])
        .expect("passkey request");

    let (apple_id, passkey) = std::thread::spawn(move || {
        apple_id
            .update(&AppleIdRequestConfiguration {
                requested_scopes: vec![AppleIdScope::FullName],
                ..AppleIdRequestConfiguration::default()
            })
            .expect("Apple ID update");
        passkey
            .update(&PlatformPasskeyAssertionOptions {
                user_verification_preference: Some(PublicKeyCredentialUserVerificationPreference::Required),
                ..PlatformPasskeyAssertionOptions::default()
            })
            .expect("passkey update");
        (apple_id, passkey)
    })
    .join()
    .expect("worker thread");

    assert_eq!(
        apple_id.configuration().expect("configuration").requested_scopes,
        vec![AppleIdScope::FullName]
    );
    assert_eq!(
        passkey.configuration().expect("configuration").user_verification_preference,
        Some(PublicKeyCredentialUserVerificationPreference::Required)
    );
}
