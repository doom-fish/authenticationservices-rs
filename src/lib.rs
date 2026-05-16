#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::unused_self
)]

pub mod account;
pub mod account_authentication_modification_controller;
pub mod authorization;
pub mod authorization_apple_id_provider;
pub mod authorization_controller;
pub mod authorization_passkey;
pub mod authorization_provider;
pub mod credential_identity_store;
pub mod error;
mod ffi;
mod private;
pub mod password_credential;
pub mod provider;
pub mod settings_helper;
pub mod web_auth_session;
pub mod web_authentication_session;

pub use account::{
    is_supported as account_request_family_is_supported,
    not_supported_error as account_request_family_not_supported_error,
    unsupported_reason as account_request_family_unsupported_reason,
    ReplacePasswordWithSignInWithAppleRequest, UpgradePasswordToStrongPasswordRequest,
};
pub use account_authentication_modification_controller::AccountAuthenticationModificationController;
pub use authorization_controller::{
    AppleIdCredential, Authorization, AuthorizationController, AuthorizationControllerRequestOptions,
    AuthorizationControllerRequests, AuthorizationGuard,
};
pub use authorization_apple_id_provider::{
    AppleIdCredentialState, AppleIdOperation, AppleIdProvider, AppleIdRequest,
    AppleIdRequestConfiguration, AppleIdScope,
};
pub use authorization_passkey::{
    LargeBlobAssertionInput, LargeBlobAssertionOperation, LargeBlobAssertionOutput,
    LargeBlobAssertionOutputResult, LargeBlobRegistrationInput, LargeBlobRegistrationOutput,
    LargeBlobSupportRequirement, PasskeyAssertionRequest, PasskeyRegistrationRequest,
    PlatformCredentialDescriptor, PlatformPasskeyAssertionOptions,
    PlatformPasskeyRegistrationOptions, PlatformPasskeyRequestStyle,
    PlatformPublicKeyCredentialAssertion, PlatformPublicKeyCredentialProvider,
    PlatformPublicKeyCredentialRegistration, PrfAssertionInput,
    PrfAssertionPerCredentialInput, PrfInputValues, PrfOutput, PrfRegistrationInput,
    PublicKeyCredentialAttachment, PublicKeyCredentialAttestationKind,
    PublicKeyCredentialParameters, PublicKeyCredentialResidentKeyPreference,
    PublicKeyCredentialUserVerificationPreference, SecurityKeyAssertionOptions,
    SecurityKeyAssertionRequest, SecurityKeyCredentialDescriptor,
    SecurityKeyPublicKeyCredentialAssertion, SecurityKeyPublicKeyCredentialProvider,
    SecurityKeyPublicKeyCredentialRegistration, SecurityKeyRegistrationOptions,
    SecurityKeyRegistrationRequest, SecurityKeyTransport,
};
pub use authorization_provider::{
    authorization_provider_protocol_name, supported_authorization_provider_kinds,
    AuthorizationProviderKind, PasswordProvider, PasswordRequest, RequestKind,
};
pub use credential_identity_store::{
    CredentialIdentity, CredentialIdentityStore, CredentialIdentityStoreState,
    CredentialIdentityTypes, CredentialServiceIdentifier, CredentialServiceIdentifierType,
    OneTimeCodeCredentialIdentity, PasskeyCredentialIdentity, PasswordCredentialIdentity,
};
pub use error::AuthenticationServicesError;
pub use password_credential::PasswordCredential;
pub use settings_helper::SettingsHelper;
pub use web_authentication_session::{
    WebAuthenticationCallback, WebAuthenticationSession, WebAuthenticationSessionGuard,
    WebAuthenticationSessionInfo,
};

/// Common imports.
pub mod prelude {
    pub use crate::{
        account_request_family_is_supported, account_request_family_not_supported_error,
        account_request_family_unsupported_reason, AccountAuthenticationModificationController,
        AppleIdCredential, AppleIdCredentialState,
        AppleIdOperation, AppleIdProvider, AppleIdRequest, AppleIdRequestConfiguration,
        AppleIdScope, Authorization, AuthorizationController,
        AuthorizationControllerRequestOptions, AuthorizationControllerRequests,
        AuthorizationGuard, AuthorizationProviderKind, CredentialIdentity,
        authorization_provider_protocol_name, supported_authorization_provider_kinds,
        CredentialIdentityStore, CredentialIdentityStoreState, CredentialIdentityTypes,
        CredentialServiceIdentifier, CredentialServiceIdentifierType, LargeBlobAssertionInput,
        LargeBlobAssertionOperation, LargeBlobAssertionOutput,
        LargeBlobAssertionOutputResult, LargeBlobRegistrationInput,
        LargeBlobRegistrationOutput, LargeBlobSupportRequirement, OneTimeCodeCredentialIdentity,
        PasskeyAssertionRequest, PasskeyCredentialIdentity, PasskeyRegistrationRequest,
        PasswordCredential, PasswordCredentialIdentity, PasswordProvider, PasswordRequest,
        PlatformCredentialDescriptor, PlatformPasskeyAssertionOptions,
        PlatformPasskeyRegistrationOptions, PlatformPasskeyRequestStyle,
        PlatformPublicKeyCredentialAssertion, PlatformPublicKeyCredentialProvider,
        PlatformPublicKeyCredentialRegistration, PrfAssertionInput,
        PrfAssertionPerCredentialInput, PrfInputValues, PrfOutput, PrfRegistrationInput,
        PublicKeyCredentialAttachment, PublicKeyCredentialAttestationKind,
        PublicKeyCredentialParameters, PublicKeyCredentialResidentKeyPreference,
        PublicKeyCredentialUserVerificationPreference, RequestKind,
        ReplacePasswordWithSignInWithAppleRequest, SecurityKeyAssertionOptions,
        SecurityKeyAssertionRequest,
        SecurityKeyCredentialDescriptor, SecurityKeyPublicKeyCredentialAssertion,
        SecurityKeyPublicKeyCredentialProvider, SecurityKeyPublicKeyCredentialRegistration,
        SecurityKeyRegistrationOptions, SecurityKeyRegistrationRequest, SecurityKeyTransport,
        SettingsHelper, UpgradePasswordToStrongPasswordRequest, WebAuthenticationCallback,
        WebAuthenticationSession, WebAuthenticationSessionGuard, WebAuthenticationSessionInfo,
    };
}
