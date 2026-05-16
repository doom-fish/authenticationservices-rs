//! Backward-compatible re-exports for provider and request-builder types.

pub use crate::authorization_apple_id_provider::{
    AppleIdCredentialState, AppleIdOperation, AppleIdProvider, AppleIdRequest,
    AppleIdRequestConfiguration, AppleIdScope,
};
pub use crate::authorization_passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, PlatformPublicKeyCredentialProvider,
    SecurityKeyAssertionOptions, SecurityKeyAssertionRequest, SecurityKeyCredentialDescriptor,
    SecurityKeyPublicKeyCredentialProvider, SecurityKeyRegistrationOptions,
    SecurityKeyRegistrationRequest,
};
pub use crate::authorization_provider::{
    authorization_provider_protocol_name, supported_authorization_provider_kinds,
    AuthorizationProviderKind, PasswordProvider, PasswordRequest, RequestKind,
};
