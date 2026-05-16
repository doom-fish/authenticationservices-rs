use authenticationservices::{
    authorization_provider_protocol_name, supported_authorization_provider_kinds, PasswordProvider,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("protocol: {}", authorization_provider_protocol_name()?);
    println!("supported kinds: {:?}", supported_authorization_provider_kinds()?);
    println!("password provider: {:?}", PasswordProvider::new());
    Ok(())
}
