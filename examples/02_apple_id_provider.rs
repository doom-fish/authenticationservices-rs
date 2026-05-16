use authenticationservices::{AppleIdProvider, AppleIdRequestConfiguration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = AppleIdProvider::new();
    let defaults = AppleIdRequestConfiguration::default();
    println!("default Apple ID scopes: {:?}", defaults.requested_scopes);
    println!(
        "credential revoked notification: {}",
        provider.credential_revoked_notification()?
    );
    Ok(())
}
