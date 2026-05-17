use authenticationservices::Authorization;

fn main() {
    let authorization = Authorization {
        provider: "apple_id".into(),
        user_identifier: Some("apple-user-123".into()),
        email: Some("alice@example.com".into()),
        full_name: Some("Alice Example".into()),
        identity_token: Some("identity-token".into()),
        authorization_code: Some("authorization-code".into()),
        real_user_status: Some(authenticationservices::UserDetectionStatus::LikelyReal),
        user_age_range: Some(authenticationservices::UserAgeRange::NotChild),
        password: None,
        credential_id: None,
        raw_attestation_object: None,
        raw_authenticator_data: None,
        signature: None,
        user_id: None,
        attachment: None,
        used_app_id: None,
        transports: None,
        large_blob_result_kind: None,
        large_blob_data: None,
        large_blob_write_succeeded: None,
        large_blob_supported: None,
        prf_first: None,
        prf_second: None,
        prf_supported: None,
    };

    println!("decoded Apple ID credential: {:?}", authorization.apple_id_credential());
}
