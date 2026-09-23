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

#[test]
fn passkey_assertion_debug_output_redacts_signatures_user_ids_and_prf_outputs() {
    use authenticationservices::{
        LargeBlobAssertionOutput, LargeBlobAssertionOutputResult, PlatformPublicKeyCredentialAssertion,
        PrfOutput, SecurityKeyPublicKeyCredentialAssertion,
    };

    let assertion = PlatformPublicKeyCredentialAssertion {
        credential_id: vec![1, 2, 3],
        raw_authenticator_data: vec![4, 5, 6],
        signature: vec![0xAB; 8],
        user_id: vec![0xCD; 8],
        attachment: None,
        large_blob: Some(LargeBlobAssertionOutput {
            result: LargeBlobAssertionOutputResult::Read(vec![0xEE; 8]),
        }),
        prf: Some(PrfOutput {
            first: Some(vec![0xF1; 8]),
            second: Some(vec![0xF2; 8]),
            is_supported: Some(true),
        }),
    };
    let rendered = format!("{assertion:?}");
    for leaked in ["171", "205", "238", "241", "242"] {
        assert!(!rendered.contains(leaked), "{leaked} leaked: {rendered}");
    }
    assert!(rendered.contains("credential_id: [1, 2, 3]"), "{rendered}");

    let security_key = SecurityKeyPublicKeyCredentialAssertion {
        credential_id: vec![1],
        raw_authenticator_data: vec![2],
        signature: vec![0xAB; 4],
        user_id: vec![0xCD; 4],
        used_app_id: None,
    };
    let rendered = format!("{security_key:?}");
    assert!(!rendered.contains("171") && !rendered.contains("205"), "{rendered}");
}
