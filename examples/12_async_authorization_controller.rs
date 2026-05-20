#[cfg(feature = "async")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use authenticationservices::async_api::AsyncAuthorizationController;
    use authenticationservices::{
        AppleIdProvider, AuthorizationControllerRequestOptions, AuthorizationControllerRequests,
    };

    pollster::block_on(async {
        let provider = AppleIdProvider::new();
        let request = provider.create_request(None)?;
        let controller = AsyncAuthorizationController::new();
        let authorization = controller
            .perform_requests_with_options(
                AuthorizationControllerRequests {
                    apple_id: Some(&request),
                    ..Default::default()
                },
                AuthorizationControllerRequestOptions::PREFER_IMMEDIATELY_AVAILABLE_CREDENTIALS,
            )?
            .await?;

        println!("provider={}", authorization.provider);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[cfg(not(feature = "async"))]
fn main() {}
