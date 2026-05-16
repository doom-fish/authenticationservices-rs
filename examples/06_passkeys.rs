use authenticationservices::{
    PlatformCredentialDescriptor, PlatformPublicKeyCredentialProvider, SecurityKeyCredentialDescriptor,
    SecurityKeyTransport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = PlatformPublicKeyCredentialProvider::new("example.com");
    println!("platform RP ID: {}", provider.relying_party_identifier());

    let descriptor = PlatformCredentialDescriptor::new(b"platform-credential".to_vec())?;
    println!("platform descriptor bytes: {}", descriptor.credential_id.len());

    let security_descriptor =
        SecurityKeyCredentialDescriptor::new(b"security-credential".to_vec(), Some(vec![SecurityKeyTransport::Usb]))?;
    println!("security-key transports: {:?}", security_descriptor.transports);
    Ok(())
}
