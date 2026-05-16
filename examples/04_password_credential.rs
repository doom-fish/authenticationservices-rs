use authenticationservices::PasswordCredential;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credential = PasswordCredential::new("alice@example.com", "correct horse battery staple")?;
    println!("password credential user: {}", credential.user);
    Ok(())
}
