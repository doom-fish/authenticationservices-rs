use authenticationservices::{
    PlatformCredentialDescriptor, PlatformPublicKeyCredentialProvider, SecurityKeyCredentialDescriptor,
    SecurityKeyTransport,
};

#[test]
fn passkey_providers_and_descriptors_round_trip() {
    let provider = PlatformPublicKeyCredentialProvider::new("example.com");
    assert_eq!(provider.relying_party_identifier(), "example.com");

    let platform_descriptor = PlatformCredentialDescriptor::new(b"platform-credential".to_vec()).unwrap();
    assert_eq!(platform_descriptor.credential_id, b"platform-credential".to_vec());

    let security_descriptor =
        SecurityKeyCredentialDescriptor::new(b"security-credential".to_vec(), Some(vec![SecurityKeyTransport::Usb]))
            .unwrap();
    assert_eq!(security_descriptor.credential_id, b"security-credential".to_vec());
    assert_eq!(security_descriptor.transports, Some(vec![SecurityKeyTransport::Usb]));
}
