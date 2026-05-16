use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use authenticationservices::{
    AppleIdProvider, PasswordProvider, PlatformPublicKeyCredentialProvider,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("AUTHSERVICES_SMOKE_BUNDLED").is_none() {
        return relaunch_inside_app_bundle();
    }

    let apple_id_provider = AppleIdProvider::new();
    let apple_id_request = apple_id_provider.create_request(Some(&["fullName", "email"]))?;
    let apple_id_kind = apple_id_request.kind()?;
    println!("Apple ID request kind: {}", apple_id_kind.kind);

    let password_provider = PasswordProvider::new();
    let password_request = password_provider.create_request()?;
    let password_kind = password_request.kind()?;
    println!("Password request kind: {}", password_kind.kind);

    let passkey_provider = PlatformPublicKeyCredentialProvider::new("example.com");
    let challenge = b"server-challenge-bytes-32-chars!!";
    let user_id = b"user-id-bytes";
    let passkey_reg = passkey_provider.create_registration_request(
        challenge,
        user_id,
        "alice@example.com",
        Some("Alice Example"),
    )?;
    let reg_kind = passkey_reg.kind()?;
    println!("Passkey registration request kind: {}", reg_kind.kind);
    println!(
        "  relying_party_identifier: {}",
        reg_kind.relying_party_identifier.as_deref().unwrap_or("")
    );
    println!(
        "  user_name: {}",
        reg_kind.user_name.as_deref().unwrap_or("")
    );

    let passkey_assert = passkey_provider.create_assertion_request(challenge)?;
    let assert_kind = passkey_assert.kind()?;
    println!("Passkey assertion request kind: {}", assert_kind.kind);
    println!(
        "  relying_party_identifier: {}",
        assert_kind
            .relying_party_identifier
            .as_deref()
            .unwrap_or("")
    );

    println!("✅ authenticationservices provider OK");
    Ok(())
}

fn relaunch_inside_app_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let crate_root = env::current_dir()?;
    let app_root = crate_root.join("target/authservices-smoke.app");
    let contents_dir = app_root.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let bundle_exe = macos_dir.join(executable_name(&current_exe));

    fs::create_dir_all(&macos_dir)?;
    fs::copy(&current_exe, &bundle_exe)?;
    fs::set_permissions(&bundle_exe, fs::metadata(&current_exe)?.permissions())?;
    fs::write(contents_dir.join("Info.plist"), info_plist())?;

    let status = Command::new(&bundle_exe)
        .env("AUTHSERVICES_SMOKE_BUNDLED", "1")
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("bundled smoke runner exited with status {status}").into())
    }
}

fn executable_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map_or_else(
            || "01_authenticationservices_smoke".to_owned(),
            ToOwned::to_owned,
        )
}

fn info_plist() -> String {
    [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
        "<plist version=\"1.0\">",
        "<dict>",
        "  <key>CFBundleExecutable</key>",
        "  <string>01_authenticationservices_smoke</string>",
        "  <key>CFBundleIdentifier</key>",
        "  <string>fish.doom.authenticationservices.smoke</string>",
        "  <key>CFBundleName</key>",
        "  <string>authservices-smoke</string>",
        "  <key>CFBundlePackageType</key>",
        "  <string>APPL</string>",
        "  <key>LSMinimumSystemVersion</key>",
        "  <string>12.0</string>",
        "</dict>",
        "</plist>",
    ]
    .join("\n")
}
