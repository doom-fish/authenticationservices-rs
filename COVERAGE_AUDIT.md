# authenticationservices-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 164
VERIFIED: 75
GAPS: 89
EXEMPT: 0
COVERAGE_PCT: 45.73%

> macOS-unavailable symbols were filtered out per the audit instructions. This removes the `ASAccountAuthenticationModification*` family and other iOS-only APIs from the denominator, so the crate's explicit macOS placeholders are noted here but not scored.

## 🟢 VERIFIED
| Symbol | Kind | Header | Wrapped by |
| --- | --- | --- | --- |
| `ASAuthorization` | interface | `ASAuthorization.h` | Authorization |
| `ASAuthorizationScope` | typedef | `ASAuthorization.h` | AppleIdScope |
| `ASAuthorizationScopeEmail` | constant | `ASAuthorization.h` | AppleIdScope::Email |
| `ASAuthorizationScopeFullName` | constant | `ASAuthorization.h` | AppleIdScope::FullName |
| `ASAuthorizationAppleIDCredential` | interface | `ASAuthorizationAppleIDCredential.h` | AppleIdCredential |
| `ASAuthorizationAppleIDProvider` | interface | `ASAuthorizationAppleIDProvider.h` | AppleIdProvider |
| `ASAuthorizationAppleIDProviderCredentialRevokedNotification` | constant | `ASAuthorizationAppleIDProvider.h` | AppleIdProvider::credential_revoked_notification |
| `ASAuthorizationAppleIDProviderCredentialState` | enum | `ASAuthorizationAppleIDProvider.h` | AppleIdCredentialState |
| `ASAuthorizationAppleIDRequest` | interface | `ASAuthorizationAppleIDRequest.h` | AppleIdRequest / AppleIdRequestConfiguration |
| `ASAuthorizationController` | interface | `ASAuthorizationController.h` | AuthorizationController / AuthorizationGuard |
| `ASAuthorizationControllerRequestOptions` | enum | `ASAuthorizationController.h` | AuthorizationControllerRequestOptions |
| `ASAuthorizationOpenIDOperation` | typedef | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation |
| `ASAuthorizationOperationImplicit` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Implicit |
| `ASAuthorizationOperationLogin` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Login |
| `ASAuthorizationOperationLogout` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Logout |
| `ASAuthorizationOperationRefresh` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Refresh |
| `ASAuthorizationPasswordProvider` | interface | `ASAuthorizationPasswordProvider.h` | PasswordProvider |
| `ASAuthorizationPasswordRequest` | interface | `ASAuthorizationPasswordRequest.h` | PasswordRequest |
| `ASAuthorizationPlatformPublicKeyCredentialAssertion` | interface | `ASAuthorizationPlatformPublicKeyCredentialAssertion.h` | PlatformPublicKeyCredentialAssertion |
| `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest` | interface | `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest.h` | PasskeyAssertionRequest / PlatformPasskeyAssertionOptions |
| `ASAuthorizationPlatformPublicKeyCredentialDescriptor` | interface | `ASAuthorizationPlatformPublicKeyCredentialDescriptor.h` | PlatformCredentialDescriptor |
| `ASAuthorizationPlatformPublicKeyCredentialProvider` | interface | `ASAuthorizationPlatformPublicKeyCredentialProvider.h` | PlatformPublicKeyCredentialProvider |
| `ASAuthorizationPlatformPublicKeyCredentialRegistration` | interface | `ASAuthorizationPlatformPublicKeyCredentialRegistration.h` | PlatformPublicKeyCredentialRegistration |
| `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest` | interface | `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.h` | PasskeyRegistrationRequest / PlatformPasskeyRegistrationOptions |
| `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequestStyle` | enum | `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.h` | PlatformPasskeyRequestStyle |
| `ASAuthorizationProvider` | protocol | `ASAuthorizationProvider.h` | authorization_provider_protocol_name / supported_authorization_provider_kinds |
| `ASAuthorizationPublicKeyCredentialAttachment` | enum | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttachment |
| `ASAuthorizationPublicKeyCredentialAttestationKind` | typedef | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind |
| `ASAuthorizationPublicKeyCredentialAttestationKindDirect` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind::Direct |
| `ASAuthorizationPublicKeyCredentialAttestationKindEnterprise` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind::Enterprise |
| `ASAuthorizationPublicKeyCredentialAttestationKindIndirect` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind::Indirect |
| `ASAuthorizationPublicKeyCredentialAttestationKindNone` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind::None |
| `ASAuthorizationPublicKeyCredentialResidentKeyPreference` | typedef | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialResidentKeyPreference |
| `ASAuthorizationPublicKeyCredentialResidentKeyPreferenceDiscouraged` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialResidentKeyPreference::Discouraged |
| `ASAuthorizationPublicKeyCredentialResidentKeyPreferencePreferred` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialResidentKeyPreference::Preferred |
| `ASAuthorizationPublicKeyCredentialResidentKeyPreferenceRequired` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialResidentKeyPreference::Required |
| `ASAuthorizationPublicKeyCredentialUserVerificationPreference` | typedef | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialUserVerificationPreference |
| `ASAuthorizationPublicKeyCredentialUserVerificationPreferenceDiscouraged` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialUserVerificationPreference::Discouraged |
| `ASAuthorizationPublicKeyCredentialUserVerificationPreferencePreferred` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialUserVerificationPreference::Preferred |
| `ASAuthorizationPublicKeyCredentialUserVerificationPreferenceRequired` | constant | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialUserVerificationPreference::Required |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.h` | LargeBlobAssertionInput |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOperation` | enum | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.h` | LargeBlobAssertionOperation |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput.h` | LargeBlobAssertionOutput |
| `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.h` | LargeBlobRegistrationInput |
| `ASAuthorizationPublicKeyCredentialLargeBlobSupportRequirement` | enum | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.h` | LargeBlobSupportRequirement |
| `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationOutput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationOutput.h` | LargeBlobRegistrationOutput |
| `ASAuthorizationPublicKeyCredentialPRFAssertionInput` | interface | `ASAuthorizationPublicKeyCredentialPRFAssertionInput.h` | PrfAssertionInput / PrfAssertionPerCredentialInput |
| `ASAuthorizationPublicKeyCredentialPRFAssertionInputValues` | interface | `ASAuthorizationPublicKeyCredentialPRFAssertionInput.h` | PrfInputValues |
| `ASAuthorizationPublicKeyCredentialPRFAssertionOutput` | interface | `ASAuthorizationPublicKeyCredentialPRFAssertionOutput.h` | PrfOutput |
| `ASAuthorizationPublicKeyCredentialPRFRegistrationInput` | interface | `ASAuthorizationPublicKeyCredentialPRFRegistrationInput.h` | PrfRegistrationInput |
| `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput` | interface | `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput.h` | PrfOutput |
| `ASAuthorizationPublicKeyCredentialParameters` | interface | `ASAuthorizationPublicKeyCredentialParameters.h` | PublicKeyCredentialParameters |
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion.h` | SecurityKeyPublicKeyCredentialAssertion |
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest.h` | SecurityKeyAssertionRequest / SecurityKeyAssertionOptions |
| `ASAuthorizationAllSupportedPublicKeyCredentialDescriptorTransports` | function | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyTransport::AllSupported |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyCredentialDescriptor |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransport` | typedef | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyTransport |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportBluetooth` | constant | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyTransport::Bluetooth |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportNFC` | constant | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyTransport::Nfc |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptorTransportUSB` | constant | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyTransport::Usb |
| `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialProvider.h` | SecurityKeyPublicKeyCredentialProvider |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration.h` | SecurityKeyPublicKeyCredentialRegistration |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest.h` | SecurityKeyRegistrationRequest / SecurityKeyRegistrationOptions |
| `ASCredentialIdentityStore` | interface | `ASCredentialIdentityStore.h` | CredentialIdentityStore (partial: state/model wrappers; mutation/listing calls return NotSupported on macOS) |
| `ASCredentialIdentityTypes` | enum | `ASCredentialIdentityStore.h` | CredentialIdentityTypes |
| `ASCredentialIdentityStoreState` | interface | `ASCredentialIdentityStoreState.h` | CredentialIdentityStoreState |
| `ASCredentialServiceIdentifier` | interface | `ASCredentialServiceIdentifier.h` | CredentialServiceIdentifier |
| `ASCredentialServiceIdentifierType` | enum | `ASCredentialServiceIdentifier.h` | CredentialServiceIdentifierType |
| `ASOneTimeCodeCredentialIdentity` | interface | `ASOneTimeCodeCredentialIdentity.h` | OneTimeCodeCredentialIdentity |
| `ASPasskeyCredentialIdentity` | interface | `ASPasskeyCredentialIdentity.h` | PasskeyCredentialIdentity |
| `ASPasswordCredential` | interface | `ASPasswordCredential.h` | PasswordCredential |
| `ASPasswordCredentialIdentity` | interface | `ASPasswordCredentialIdentity.h` | PasswordCredentialIdentity |
| `ASSettingsHelper` | interface | `ASSettingsHelper.h` | SettingsHelper |
| `ASWebAuthenticationSession` | interface | `ASWebAuthenticationSession.h` | WebAuthenticationSession / WebAuthenticationSessionGuard / WebAuthenticationSessionInfo |
| `ASWebAuthenticationSessionCallback` | interface | `ASWebAuthenticationSessionCallback.h` | WebAuthenticationCallback |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| `ASAuthorizationAppleIDButton` | interface | `ASAuthorizationAppleIDButton.h` | Apple ID button UI helpers are not wrapped. |
| `ASAuthorizationAppleIDButtonStyle` | enum | `ASAuthorizationAppleIDButton.h` | Apple ID button UI helpers are not wrapped. |
| `ASAuthorizationAppleIDButtonType` | enum | `ASAuthorizationAppleIDButton.h` | Apple ID button UI helpers are not wrapped. |
| `ASUserAgeRange` | enum | `ASAuthorizationAppleIDCredential.h` | Decoded Apple ID wrappers omit these availability enums. |
| `ASUserDetectionStatus` | enum | `ASAuthorizationAppleIDCredential.h` | Decoded Apple ID wrappers omit these availability enums. |
| `ASAuthorizationControllerDelegate` | protocol | `ASAuthorizationController.h` | Hidden behind internal Swift delegates/callbacks; no public Rust protocol wrapper. |
| `ASAuthorizationControllerPresentationContextProviding` | protocol | `ASAuthorizationController.h` | Hidden behind internal Swift delegates/callbacks; no public Rust protocol wrapper. |
| `ASAuthorizationCredential` | protocol | `ASAuthorizationCredential.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationErrorDomain` | constant | `ASAuthorizationError.h` | NSError domain/constants are not exposed as a stable Rust API. |
| `ASAuthorizationOpenIDRequest` | interface | `ASAuthorizationOpenIDRequest.h` | No public Rust wrapper. |
| `ASAuthorizationProviderAuthorizationOperation` | typedef | `ASAuthorizationProviderExtensionAuthorizationRequest.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderAuthorizationOperationConfigurationRemoved` | constant | `ASAuthorizationProviderExtensionAuthorizationRequest.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderAuthorizationOperationDirectRequest` | constant | `ASAuthorizationProviderExtensionAuthorizationRequest.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionAuthorizationRequest` | interface | `ASAuthorizationProviderExtensionAuthorizationRequest.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionAuthorizationRequestHandler` | protocol | `ASAuthorizationProviderExtensionAuthorizationRequest.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionAuthorizationResult` | interface | `ASAuthorizationProviderExtensionAuthorizationResult.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmECDHE_A256GCM` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_Curve25519_SHA256_ChachaPoly` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_P256_SHA256_AES_GCM_256` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_P384_SHA384_AES_GCM_256` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionFederationType` | enum | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionKerberosMapping` | interface | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionLoginConfiguration` | interface | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionSigningAlgorithm` | typedef | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionSigningAlgorithmES256` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionSigningAlgorithmES384` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionSigningAlgorithmEd25519` | constant | `ASAuthorizationProviderExtensionLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionAuthenticationMethod` | enum | `ASAuthorizationProviderExtensionLoginManager.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionKeyType` | enum | `ASAuthorizationProviderExtensionLoginManager.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionLoginManager` | interface | `ASAuthorizationProviderExtensionLoginManager.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionAuthenticationMethod` | enum | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionPlatformSSOProtocolVersion` | enum | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionRegistrationHandler` | protocol | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionRegistrationResult` | enum | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionRequestOptions` | enum | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionSupportedGrantTypes` | enum | `ASAuthorizationProviderExtensionRegistrationHandler.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationProviderExtensionUserLoginConfiguration` | interface | `ASAuthorizationProviderExtensionUserLoginConfiguration.h` | Provider-extension / Platform SSO APIs are not wrapped. |
| `ASAuthorizationPublicKeyCredentialAssertion` | protocol | `ASAuthorizationPublicKeyCredentialAssertion.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationPublicKeyCredentialAssertionRequest.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationPublicKeyCredentialDescriptor` | protocol | `ASAuthorizationPublicKeyCredentialDescriptor.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationPublicKeyCredentialRegistration` | protocol | `ASAuthorizationPublicKeyCredentialRegistration.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationPublicKeyCredentialRegistrationRequest.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationRequest` | interface | `ASAuthorizationRequest.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASAuthorizationSingleSignOnCredential` | interface | `ASAuthorizationSingleSignOnCredential.h` | Single sign-on provider APIs are not wrapped. |
| `ASAuthorizationSingleSignOnProvider` | interface | `ASAuthorizationSingleSignOnProvider.h` | Single sign-on provider APIs are not wrapped. |
| `ASAuthorizationSingleSignOnRequest` | interface | `ASAuthorizationSingleSignOnRequest.h` | Single sign-on provider APIs are not wrapped. |
| `ASAuthorizationWebBrowserExternallyAuthenticatableRequest` | protocol | `ASAuthorizationWebBrowserExternallyAuthenticatableRequest.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredential` | interface | `ASAuthorizationWebBrowserPlatformPublicKeyCredential.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPublicKeyCredentialManager` | interface | `ASAuthorizationWebBrowserPublicKeyCredentialManager.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserPublicKeyCredentialManagerAuthorizationState` | enum | `ASAuthorizationWebBrowserPublicKeyCredentialManager.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASCOSEAlgorithmIdentifier` | typedef | `ASCOSEConstants.h` | COSE identifier typedefs are not exposed. |
| `ASCOSEEllipticCurveIdentifier` | typedef | `ASCOSEConstants.h` | COSE identifier typedefs are not exposed. |
| `ASCredentialIdentity` | protocol | `ASCredentialIdentity.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASCredentialIdentityStoreErrorDomain` | constant | `ASCredentialIdentityStore.h` | NSError domain/constants are not exposed as a stable Rust API. |
| `ASCredentialProviderExtensionContext` | interface | `ASCredentialProviderExtensionContext.h` | Credential Provider extension APIs are not wrapped. |
| `ASCredentialProviderViewController` | interface | `ASCredentialProviderViewController.h` | Credential Provider extension APIs are not wrapped. |
| `ASCredentialRequest` | protocol | `ASCredentialRequest.h` | Credential Provider extension APIs are not wrapped. |
| `ASCredentialRequestType` | enum | `ASCredentialRequest.h` | Credential Provider extension APIs are not wrapped. |
| `ASExtensionErrorDomain` | constant | `ASExtensionErrors.h` | NSError domain/constants are not exposed as a stable Rust API. |
| `ASImage` | typedef | `ASFoundation.h` | Used internally by the Swift bridge only; no public Rust alias. |
| `ASPresentationAnchor` | typedef | `ASFoundation.h` | Used internally by the Swift bridge only; no public Rust alias. |
| `ASViewController` | typedef | `ASFoundation.h` | Used internally by the Swift bridge only; no public Rust alias. |
| `ASOneTimeCodeCredential` | interface | `ASOneTimeCodeCredential.h` | Credential-provider credential/request APIs are not wrapped. |
| `ASOneTimeCodeCredentialRequest` | interface | `ASOneTimeCodeCredentialRequest.h` | Credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyAssertionCredential` | interface | `ASPasskeyAssertionCredential.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyAssertionCredentialExtensionInput` | interface | `ASPasskeyAssertionCredentialExtensionInput.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyAssertionCredentialExtensionOutput` | interface | `ASPasskeyAssertionCredentialExtensionOutput.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyCredentialRequest` | interface | `ASPasskeyCredentialRequest.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyCredentialRequestParameters` | interface | `ASPasskeyCredentialRequestParameters.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyRegistrationCredential` | interface | `ASPasskeyRegistrationCredential.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyRegistrationCredentialExtensionInput` | interface | `ASPasskeyRegistrationCredentialExtensionInput.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasskeyRegistrationCredentialExtensionOutput` | interface | `ASPasskeyRegistrationCredentialExtensionOutput.h` | Passkey credential-provider request/credential APIs are not wrapped. |
| `ASPasswordCredentialRequest` | interface | `ASPasswordCredentialRequest.h` | Credential-provider request/credential APIs are not wrapped. |
| `ASPublicKeyCredential` | protocol | `ASPublicKeyCredential.h` | Crate exposes concrete wrappers, not the shared protocol/base type. |
| `ASPublicKeyCredentialClientData` | interface | `ASPublicKeyCredentialClientData.h` | Client data is handled as raw bytes, not surfaced as a typed wrapper. |
| `ASPublicKeyCredentialClientDataCrossOriginValue` | enum | `ASPublicKeyCredentialClientData.h` | Client data is handled as raw bytes, not surfaced as a typed wrapper. |
| `ASWebAuthenticationPresentationContextProviding` | protocol | `ASWebAuthenticationSession.h` | Hidden behind internal Swift delegates/callbacks; no public Rust protocol wrapper. |
| `ASWebAuthenticationSessionCompletionHandler` | typedef | `ASWebAuthenticationSession.h` | No public Rust wrapper. |
| `ASWebAuthenticationSessionErrorDomain` | constant | `ASWebAuthenticationSession.h` | NSError domain/constants are not exposed as a stable Rust API. |
| `ASWebAuthenticationSessionRequest` | interface | `ASWebAuthenticationSessionRequest.h` | No public Rust wrapper. |
| `ASWebAuthenticationSessionRequestDelegate` | protocol | `ASWebAuthenticationSessionRequest.h` | Hidden behind internal Swift delegates/callbacks; no public Rust protocol wrapper. |
| `ASWebAuthenticationSessionWebBrowserSessionHandling` | protocol | `ASWebAuthenticationSessionWebBrowserSessionHandling.h` | Web-browser public-key-credential APIs are not wrapped. |
| `ASWebAuthenticationSessionWebBrowserSessionManager` | interface | `ASWebAuthenticationSessionWebBrowserSessionManager.h` | Web-browser public-key-credential APIs are not wrapped. |

## ⏭️ EXEMPT
| Symbol | Kind | Header | Reason | SDK attribute |
| --- | --- | --- | --- | --- |
| _None_ | - | - | - | - |
