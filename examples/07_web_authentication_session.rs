use authenticationservices::{WebAuthenticationCallback, WebAuthenticationSession};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let callback = WebAuthenticationCallback::CustomScheme("demo".into());
    println!(
        "custom callback matches demo:// URL: {}",
        callback.matches_url("demo://callback?code=123")?
    );

    let session = WebAuthenticationSession::new("https://example.com/login", Some("demo"))
        .with_prefers_ephemeral_web_browser_session(true)
        .with_additional_header_field("X-Demo", "1");
    println!("session builder: {session:?}");
    Ok(())
}
