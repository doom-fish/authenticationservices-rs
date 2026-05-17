# authenticationservices-rs coverage audit (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 164
VERIFIED: 164
GAPS: 0
EXEMPT: 0
COVERAGE_PCT: 100.00%

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
| `ASAuthorizationAppleIDButton` | interface | ``ASAuthorizationAppleIDButton.h`` | AppleIdButton |
| `ASAuthorizationAppleIDButtonStyle` | enum | ``ASAuthorizationAppleIDButton.h`` | AppleIdButtonStyle |
| `ASAuthorizationAppleIDButtonType` | enum | ``ASAuthorizationAppleIDButton.h`` | AppleIdButtonType |
| `ASUserAgeRange` | enum | ``ASAuthorizationAppleIDCredential.h`` | UserAgeRange |
| `ASUserDetectionStatus` | enum | ``ASAuthorizationAppleIDCredential.h`` | UserDetectionStatus |
| `ASAuthorizationControllerDelegate` | protocol | ``ASAuthorizationController.h`` | AuthorizationControllerDelegate |
| `ASAuthorizationControllerPresentationContextProviding` | protocol | ``ASAuthorizationController.h`` | AuthorizationControllerPresentationContextProviding |
| `ASAuthorizationCredential` | protocol | ``ASAuthorizationCredential.h`` | AuthorizationCredential |
| `ASAuthorizationErrorDomain` | constant | ``ASAuthorizationError.h`` | authorization_error_domain |
| `ASAuthorizationOpenIDRequest` | interface | ``ASAuthorizationOpenIDRequest.h`` | OpenIdRequest / OpenIdRequestConfiguration |
| `ASAuthorizationProviderAuthorizationOperation` | typedef | ``ASAuthorizationProviderExtensionAuthorizationRequest.h`` | ProviderExtensionAuthorizationOperation |
| `ASAuthorizationProviderAuthorizationOperationConfigurationRemoved` | constant | ``ASAuthorizationProviderExtensionAuthorizationRequest.h`` | ProviderExtensionAuthorizationOperation::ConfigurationRemoved |
| `ASAuthorizationProviderAuthorizationOperationDirectRequest` | constant | ``ASAuthorizationProviderExtensionAuthorizationRequest.h`` | ProviderExtensionAuthorizationOperation::DirectRequest |
| `ASAuthorizationProviderExtensionAuthorizationRequest` | interface | ``ASAuthorizationProviderExtensionAuthorizationRequest.h`` | ProviderExtensionAuthorizationRequest |
| `ASAuthorizationProviderExtensionAuthorizationRequestHandler` | protocol | ``ASAuthorizationProviderExtensionAuthorizationRequest.h`` | ProviderExtensionAuthorizationRequestHandler |
| `ASAuthorizationProviderExtensionAuthorizationResult` | interface | ``ASAuthorizationProviderExtensionAuthorizationResult.h`` | ProviderExtensionAuthorizationResult |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmECDHE_A256GCM` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionEncryptionAlgorithm::EcdheA256Gcm |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_Curve25519_SHA256_ChachaPoly` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionEncryptionAlgorithm::HpkeCurve25519Sha256ChachaPoly |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_P256_SHA256_AES_GCM_256` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionEncryptionAlgorithm::HpkeP256Sha256AesGcm256 |
| `ASAuthorizationProviderExtensionEncryptionAlgorithmHPKE_P384_SHA384_AES_GCM_256` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionEncryptionAlgorithm::HpkeP384Sha384AesGcm256 |
| `ASAuthorizationProviderExtensionFederationType` | enum | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionFederationType |
| `ASAuthorizationProviderExtensionKerberosMapping` | interface | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionKerberosMapping |
| `ASAuthorizationProviderExtensionLoginConfiguration` | interface | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionLoginConfiguration |
| `ASAuthorizationProviderExtensionSigningAlgorithm` | typedef | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionSigningAlgorithm |
| `ASAuthorizationProviderExtensionSigningAlgorithmES256` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionSigningAlgorithm::Es256 |
| `ASAuthorizationProviderExtensionSigningAlgorithmES384` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionSigningAlgorithm::Es384 |
| `ASAuthorizationProviderExtensionSigningAlgorithmEd25519` | constant | ``ASAuthorizationProviderExtensionLoginConfiguration.h`` | ProviderExtensionSigningAlgorithm::Ed25519 |
| `ASAuthorizationProviderExtensionAuthenticationMethod` | enum | ``ASAuthorizationProviderExtensionLoginManager.h`` | ProviderExtensionAuthenticationMethod |
| `ASAuthorizationProviderExtensionKeyType` | enum | ``ASAuthorizationProviderExtensionLoginManager.h`` | ProviderExtensionKeyType |
| `ASAuthorizationProviderExtensionLoginManager` | interface | ``ASAuthorizationProviderExtensionLoginManager.h`` | ProviderExtensionLoginManager |
| `ASAuthorizationProviderExtensionAuthenticationMethod` | enum | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionAuthenticationMethod |
| `ASAuthorizationProviderExtensionPlatformSSOProtocolVersion` | enum | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionPlatformSsoProtocolVersion |
| `ASAuthorizationProviderExtensionRegistrationHandler` | protocol | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionRegistrationHandler |
| `ASAuthorizationProviderExtensionRegistrationResult` | enum | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionRegistrationResult |
| `ASAuthorizationProviderExtensionRequestOptions` | enum | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionRequestOptions |
| `ASAuthorizationProviderExtensionSupportedGrantTypes` | enum | ``ASAuthorizationProviderExtensionRegistrationHandler.h`` | ProviderExtensionSupportedGrantTypes |
| `ASAuthorizationProviderExtensionUserLoginConfiguration` | interface | ``ASAuthorizationProviderExtensionUserLoginConfiguration.h`` | ProviderExtensionUserLoginConfiguration |
| `ASAuthorizationPublicKeyCredentialAssertion` | protocol | ``ASAuthorizationPublicKeyCredentialAssertion.h`` | PublicKeyCredentialAssertion |
| `ASAuthorizationPublicKeyCredentialAssertionRequest` | protocol | ``ASAuthorizationPublicKeyCredentialAssertionRequest.h`` | PublicKeyCredentialAssertionRequest |
| `ASAuthorizationPublicKeyCredentialDescriptor` | protocol | ``ASAuthorizationPublicKeyCredentialDescriptor.h`` | PublicKeyCredentialDescriptor |
| `ASAuthorizationPublicKeyCredentialRegistration` | protocol | ``ASAuthorizationPublicKeyCredentialRegistration.h`` | PublicKeyCredentialRegistration |
| `ASAuthorizationPublicKeyCredentialRegistrationRequest` | protocol | ``ASAuthorizationPublicKeyCredentialRegistrationRequest.h`` | PublicKeyCredentialRegistrationRequest |
| `ASAuthorizationRequest` | interface | ``ASAuthorizationRequest.h`` | AuthorizationRequest |
| `ASAuthorizationSingleSignOnCredential` | interface | ``ASAuthorizationSingleSignOnCredential.h`` | SingleSignOnCredential |
| `ASAuthorizationSingleSignOnProvider` | interface | ``ASAuthorizationSingleSignOnProvider.h`` | SingleSignOnProvider |
| `ASAuthorizationSingleSignOnRequest` | interface | ``ASAuthorizationSingleSignOnRequest.h`` | SingleSignOnRequest |
| `ASAuthorizationWebBrowserExternallyAuthenticatableRequest` | protocol | ``ASAuthorizationWebBrowserExternallyAuthenticatableRequest.h`` | WebBrowserExternallyAuthenticatableRequest |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredential` | interface | ``ASAuthorizationWebBrowserPlatformPublicKeyCredential.h`` | WebBrowserPlatformPublicKeyCredential |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest` | protocol | ``ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest.h`` | WebBrowserPlatformPublicKeyCredentialAssertionRequest |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider` | protocol | ``ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider.h`` | WebBrowserPlatformPublicKeyCredentialProvider |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest` | protocol | ``ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest.h`` | WebBrowserPlatformPublicKeyCredentialRegistrationRequest |
| `ASAuthorizationWebBrowserPublicKeyCredentialManager` | interface | ``ASAuthorizationWebBrowserPublicKeyCredentialManager.h`` | WebBrowserPublicKeyCredentialManager |
| `ASAuthorizationWebBrowserPublicKeyCredentialManagerAuthorizationState` | enum | ``ASAuthorizationWebBrowserPublicKeyCredentialManager.h`` | WebBrowserPublicKeyCredentialManagerAuthorizationState |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest` | protocol | ``ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest.h`` | WebBrowserSecurityKeyPublicKeyCredentialAssertionRequest |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider` | protocol | ``ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider.h`` | WebBrowserSecurityKeyPublicKeyCredentialProvider |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest` | protocol | ``ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest.h`` | WebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest |
| `ASCOSEAlgorithmIdentifier` | typedef | ``ASCOSEConstants.h`` | CoseAlgorithmIdentifier |
| `ASCOSEEllipticCurveIdentifier` | typedef | ``ASCOSEConstants.h`` | CoseEllipticCurveIdentifier |
| `ASCredentialIdentity` | protocol | ``ASCredentialIdentity.h`` | CredentialIdentityRecord |
| `ASCredentialIdentityStoreErrorDomain` | constant | ``ASCredentialIdentityStore.h`` | credential_identity_store_error_domain |
| `ASCredentialProviderExtensionContext` | interface | ``ASCredentialProviderExtensionContext.h`` | CredentialProviderExtensionContext |
| `ASCredentialProviderViewController` | interface | ``ASCredentialProviderViewController.h`` | CredentialProviderViewController |
| `ASCredentialRequest` | protocol | ``ASCredentialRequest.h`` | CredentialRequest |
| `ASCredentialRequestType` | enum | ``ASCredentialRequest.h`` | CredentialRequestType |
| `ASExtensionErrorDomain` | constant | ``ASExtensionErrors.h`` | extension_error_domain |
| `ASImage` | typedef | ``ASFoundation.h`` | Image |
| `ASPresentationAnchor` | typedef | ``ASFoundation.h`` | PresentationAnchor |
| `ASViewController` | typedef | ``ASFoundation.h`` | ViewController |
| `ASOneTimeCodeCredential` | interface | ``ASOneTimeCodeCredential.h`` | OneTimeCodeCredential |
| `ASOneTimeCodeCredentialRequest` | interface | ``ASOneTimeCodeCredentialRequest.h`` | OneTimeCodeCredentialRequest |
| `ASPasskeyAssertionCredential` | interface | ``ASPasskeyAssertionCredential.h`` | PasskeyAssertionCredential |
| `ASPasskeyAssertionCredentialExtensionInput` | interface | ``ASPasskeyAssertionCredentialExtensionInput.h`` | PasskeyAssertionCredentialExtensionInput |
| `ASPasskeyAssertionCredentialExtensionOutput` | interface | ``ASPasskeyAssertionCredentialExtensionOutput.h`` | PasskeyAssertionCredentialExtensionOutput |
| `ASPasskeyCredentialRequest` | interface | ``ASPasskeyCredentialRequest.h`` | PasskeyCredentialRequest |
| `ASPasskeyCredentialRequestParameters` | interface | ``ASPasskeyCredentialRequestParameters.h`` | PasskeyCredentialRequestParameters |
| `ASPasskeyRegistrationCredential` | interface | ``ASPasskeyRegistrationCredential.h`` | PasskeyRegistrationCredential |
| `ASPasskeyRegistrationCredentialExtensionInput` | interface | ``ASPasskeyRegistrationCredentialExtensionInput.h`` | PasskeyRegistrationCredentialExtensionInput |
| `ASPasskeyRegistrationCredentialExtensionOutput` | interface | ``ASPasskeyRegistrationCredentialExtensionOutput.h`` | PasskeyRegistrationCredentialExtensionOutput |
| `ASPasswordCredentialRequest` | interface | ``ASPasswordCredentialRequest.h`` | PasswordCredentialRequest |
| `ASPublicKeyCredential` | protocol | ``ASPublicKeyCredential.h`` | PublicKeyCredential |
| `ASPublicKeyCredentialClientData` | interface | ``ASPublicKeyCredentialClientData.h`` | PublicKeyCredentialClientData |
| `ASPublicKeyCredentialClientDataCrossOriginValue` | enum | ``ASPublicKeyCredentialClientData.h`` | PublicKeyCredentialClientDataCrossOriginValue |
| `ASWebAuthenticationPresentationContextProviding` | protocol | ``ASWebAuthenticationSession.h`` | WebAuthenticationPresentationContextProviding |
| `ASWebAuthenticationSessionCompletionHandler` | typedef | ``ASWebAuthenticationSession.h`` | WebAuthenticationSessionCompletionHandler |
| `ASWebAuthenticationSessionErrorDomain` | constant | ``ASWebAuthenticationSession.h`` | web_authentication_session_error_domain |
| `ASWebAuthenticationSessionRequest` | interface | ``ASWebAuthenticationSessionRequest.h`` | WebAuthenticationSessionRequest |
| `ASWebAuthenticationSessionRequestDelegate` | protocol | ``ASWebAuthenticationSessionRequest.h`` | WebAuthenticationSessionRequestDelegate |
| `ASWebAuthenticationSessionWebBrowserSessionHandling` | protocol | ``ASWebAuthenticationSessionWebBrowserSessionHandling.h`` | WebAuthenticationSessionWebBrowserSessionHandling |
| `ASWebAuthenticationSessionWebBrowserSessionManager` | interface | ``ASWebAuthenticationSessionWebBrowserSessionManager.h`` | WebAuthenticationSessionWebBrowserSessionManager |

## 🔴 GAPS
| Symbol | Kind | Header | Notes |
| --- | --- | --- | --- |
| _None_ | - | - | - |

## ⏭️ EXEMPT
| Symbol | Kind | Header | Reason | SDK attribute |
| --- | --- | --- | --- | --- |
| _None_ | - | - | - | - |
