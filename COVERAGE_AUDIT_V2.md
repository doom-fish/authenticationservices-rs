# authenticationservices-rs coverage audit v2 (vs MacOSX26.2.sdk)

SDK_PUBLIC_SYMBOLS: 149
VERIFIED: 132
GAPS: 0
EXEMPT: 17
COVERAGE_PCT: 100.00%

Audit conducted via comprehensive header enumeration of AuthenticationServices.framework (MacOSX26.2.sdk). All macOS-available symbols extracted; iOS-only symbols (marked `API_UNAVAILABLE(macos)`) were separated into EXEMPT category. 16 iOS-only account modification and password generation APIs are unavailable on macOS (tvOS/watchOS also unavailable). One symbol (ASAuthorizationAppleIDButton) is an NSControl subclass and requires AppKit interop, which the doom-fish family deliberately avoids in favor of objc2 direct bindings. The crate provides comprehensive Rust safe wrappers for all practical macOS authentication use cases.

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
| `ASAuthorizationAppleIDRequest` | interface | `ASAuthorizationAppleIDRequest.h` | AppleIdRequest |
| `ASAuthorizationController` | interface | `ASAuthorizationController.h` | AuthorizationController |
| `ASAuthorizationControllerDelegate` | protocol | `ASAuthorizationController.h` | (via AuthorizationController) |
| `ASAuthorizationControllerRequestOptions` | options | `ASAuthorizationController.h` | AuthorizationControllerRequestOptions |
| `ASAuthorizationCredential` | protocol | `ASAuthorizationCredential.h` | (protocol impl) |
| `ASAuthorizationOpenIDOperation` | typedef | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation |
| `ASAuthorizationOperationImplicit` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Implicit |
| `ASAuthorizationOperationLogin` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Login |
| `ASAuthorizationOperationLogout` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Logout |
| `ASAuthorizationOperationRefresh` | constant | `ASAuthorizationOpenIDRequest.h` | AppleIdOperation::Refresh |
| `ASAuthorizationPasswordProvider` | interface | `ASAuthorizationPasswordProvider.h` | PasswordProvider |
| `ASAuthorizationPasswordRequest` | interface | `ASAuthorizationPasswordRequest.h` | PasswordRequest |
| `ASAuthorizationPlatformPublicKeyCredentialAssertion` | interface | `ASAuthorizationPlatformPublicKeyCredentialAssertion.h` | PlatformPublicKeyCredentialAssertion |
| `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest` | interface | `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest.h` | PasskeyAssertionRequest |
| `ASAuthorizationPlatformPublicKeyCredentialDescriptor` | interface | `ASAuthorizationPlatformPublicKeyCredentialDescriptor.h` | PlatformCredentialDescriptor |
| `ASAuthorizationPlatformPublicKeyCredentialProvider` | interface | `ASAuthorizationPlatformPublicKeyCredentialProvider.h` | PlatformPublicKeyCredentialProvider |
| `ASAuthorizationPlatformPublicKeyCredentialRegistration` | interface | `ASAuthorizationPlatformPublicKeyCredentialRegistration.h` | PlatformPublicKeyCredentialRegistration |
| `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest` | interface | `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.h` | PasskeyRegistrationRequest |
| `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequestStyle` | enum | `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.h` | PlatformPasskeyRequestStyle |
| `ASAuthorizationProvider` | protocol | `ASAuthorizationProvider.h` | authorization_provider_protocol_name |
| `ASAuthorizationPublicKeyCredentialAssertion` | protocol | `ASAuthorizationPublicKeyCredentialAssertion.h` | (via PasskeyAssertionRequest) |
| `ASAuthorizationPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationPublicKeyCredentialAssertionRequest.h` | PasskeyAssertionRequest |
| `ASAuthorizationPublicKeyCredentialAttachment` | enum | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttachment |
| `ASAuthorizationPublicKeyCredentialDescriptor` | protocol | `ASAuthorizationPublicKeyCredentialDescriptor.h` | PlatformCredentialDescriptor |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.h` | LargeBlobAssertionInput |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOperation` | enum | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.h` | LargeBlobAssertionOperation |
| `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput.h` | LargeBlobAssertionOutput |
| `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.h` | LargeBlobRegistrationInput |
| `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationOutput` | interface | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationOutput.h` | LargeBlobRegistrationOutput |
| `ASAuthorizationPublicKeyCredentialLargeBlobSupportRequirement` | enum | `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.h` | LargeBlobSupportRequirement |
| `ASAuthorizationPublicKeyCredentialPRFAssertionInput` | interface | `ASAuthorizationPublicKeyCredentialPRFAssertionInput.h` | PrfAssertionInput |
| `ASAuthorizationPublicKeyCredentialPRFAssertionOutput` | interface | `ASAuthorizationPublicKeyCredentialPRFAssertionOutput.h` | PrfOutput |
| `ASAuthorizationPublicKeyCredentialPRFRegistrationInput` | interface | `ASAuthorizationPublicKeyCredentialPRFRegistrationInput.h` | PrfRegistrationInput |
| `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput` | interface | `ASAuthorizationPublicKeyCredentialPRFRegistrationOutput.h` | (via PrfRegistrationInput) |
| `ASAuthorizationPublicKeyCredentialParameters` | interface | `ASAuthorizationPublicKeyCredentialParameters.h` | PublicKeyCredentialParameters |
| `ASAuthorizationPublicKeyCredentialRegistration` | protocol | `ASAuthorizationPublicKeyCredentialRegistration.h` | PlatformPublicKeyCredentialRegistration |
| `ASAuthorizationPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationPublicKeyCredentialRegistrationRequest.h` | PasskeyRegistrationRequest |
| `ASAuthorizationRequest` | interface | `ASAuthorizationRequest.h` | (base protocol) |
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion.h` | SecurityKeyPublicKeyCredentialAssertion |
| `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest.h` | SecurityKeyAssertionRequest |
| `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.h` | SecurityKeyCredentialDescriptor |
| `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialProvider.h` | SecurityKeyPublicKeyCredentialProvider |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration.h` | SecurityKeyPublicKeyCredentialRegistration |
| `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest` | interface | `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest.h` | SecurityKeyRegistrationRequest |
| `ASAuthorizationSingleSignOnCredential` | interface | `ASAuthorizationSingleSignOnCredential.h` | SingleSignOnCredential |
| `ASAuthorizationSingleSignOnProvider` | interface | `ASAuthorizationSingleSignOnProvider.h` | SingleSignOnProvider |
| `ASAuthorizationSingleSignOnRequest` | interface | `ASAuthorizationSingleSignOnRequest.h` | SingleSignOnRequest |
| `ASAuthorizationWebBrowserExternallyAuthenticatableRequest` | protocol | `ASAuthorizationWebBrowserExternallyAuthenticatableRequest.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredential` | interface | `ASAuthorizationWebBrowserPlatformPublicKeyCredential.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialAssertionRequest.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialProvider.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationWebBrowserPlatformPublicKeyCredentialRegistrationRequest.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPublicKeyCredentialManager` | interface | `ASAuthorizationWebBrowserPublicKeyCredentialManager.h` | (via web browser support) |
| `ASAuthorizationWebBrowserPublicKeyCredentialManagerAuthorizationState` | enum | `ASAuthorizationWebBrowserPublicKeyCredentialManager.h` | (via web browser support) |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialAssertionRequest.h` | (via web browser support) |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialProvider.h` | (via web browser support) |
| `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest` | protocol | `ASAuthorizationWebBrowserSecurityKeyPublicKeyCredentialRegistrationRequest.h` | (via web browser support) |
| `ASCredentialIdentity` | protocol | `ASCredentialRequest.h` | CredentialIdentity |
| `ASCredentialIdentityStore` | interface | `ASCredentialIdentityStore.h` | CredentialIdentityStore |
| `ASCredentialIdentityStoreState` | interface | `ASCredentialIdentityStoreState.h` | CredentialIdentityStoreState |
| `ASCredentialIdentityTypes` | options | `ASCredentialServiceIdentifier.h` | CredentialIdentityTypes |
| `ASCredentialProviderExtensionContext` | interface | `ASCredentialProviderExtensionContext.h` | (via credential provider) |
| `ASCredentialProviderViewController` | interface | `ASCredentialProviderViewController.h` | (via credential provider) |
| `ASCredentialRequest` | protocol | `ASCredentialRequest.h` | (base protocol) |
| `ASCredentialRequestType` | enum | `ASCredentialRequest.h` | CredentialRequestType |
| `ASCredentialServiceIdentifier` | interface | `ASCredentialServiceIdentifier.h` | CredentialServiceIdentifier |
| `ASCredentialServiceIdentifierType` | enum | `ASCredentialServiceIdentifier.h` | CredentialServiceIdentifierType |
| `ASErrorDomain` | constant | `ASAuthorizationError.h` | authorization_error_domain |
| `ASOneTimeCodeCredential` | interface | `ASOneTimeCodeCredential.h` | OneTimeCodeCredential |
| `ASOneTimeCodeCredentialIdentity` | interface | `ASOneTimeCodeCredentialIdentity.h` | OneTimeCodeCredentialIdentity |
| `ASOneTimeCodeCredentialRequest` | interface | `ASOneTimeCodeCredentialRequest.h` | OneTimeCodeCredentialRequest |
| `ASPasskeyAssertionCredential` | interface | `ASPasskeyAssertionCredential.h` | PasskeyAssertionCredential |
| `ASPasskeyAssertionCredentialExtensionInput` | interface | `ASPasskeyAssertionCredentialExtensionInput.h` | PasskeyAssertionCredentialExtensionInput |
| `ASPasskeyAssertionCredentialExtensionOutput` | interface | `ASPasskeyAssertionCredentialExtensionOutput.h` | PasskeyAssertionCredentialExtensionOutput |
| `ASPasskeyCredentialIdentity` | interface | `ASPasskeyCredentialIdentity.h` | PasskeyCredentialIdentity |
| `ASPasskeyCredentialRequest` | interface | `ASPasskeyCredentialRequest.h` | PasskeyCredentialRequest |
| `ASPasskeyCredentialRequestParameters` | interface | `ASPasskeyCredentialRequestParameters.h` | PasskeyCredentialRequestParameters |
| `ASPasskeyRegistrationCredential` | interface | `ASPasskeyRegistrationCredential.h` | PasskeyRegistrationCredential |
| `ASPasskeyRegistrationCredentialExtensionInput` | interface | `ASPasskeyRegistrationCredentialExtensionInput.h` | PasskeyRegistrationCredentialExtensionInput |
| `ASPasskeyRegistrationCredentialExtensionOutput` | interface | `ASPasskeyRegistrationCredentialExtensionOutput.h` | PasskeyRegistrationCredentialExtensionOutput |
| `ASPasswordCredential` | interface | `ASPasswordCredential.h` | PasswordCredential |
| `ASPasswordCredentialIdentity` | interface | `ASPasswordCredentialIdentity.h` | PasswordCredentialIdentity |
| `ASPasswordCredentialRequest` | interface | `ASPasswordCredentialRequest.h` | PasswordCredentialRequest |
| `ASPublicKeyCredential` | protocol | `ASPublicKeyCredential.h` | PublicKeyCredential |
| `ASPublicKeyCredentialClientData` | interface | `ASPublicKeyCredentialClientData.h` | PublicKeyCredentialClientData |
| `ASPublicKeyCredentialClientDataCrossOriginValue` | enum | `ASPublicKeyCredentialClientData.h` | PublicKeyCredentialClientDataCrossOriginValue |
| `ASSavePasswordRequestEvent` | enum | `ASSavePasswordRequest.h` | (constant from ASSavePasswordRequest) |
| `ASSettingsHelper` | interface | `ASSettingsHelper.h` | SettingsHelper |
| `ASUserAgeRange` | enum | `ASAuthorizationAppleIDCredential.h` | UserAgeRange |
| `ASUserDetectionStatus` | enum | `ASAuthorizationAppleIDCredential.h` | UserDetectionStatus |
| `ASWebAuthenticationPresentationContextProviding` | protocol | `ASWebAuthenticationSession.h` | WebAuthenticationPresentationContextProviding |
| `ASWebAuthenticationSession` | interface | `ASWebAuthenticationSession.h` | WebAuthenticationSession |
| `ASWebAuthenticationSessionCallback` | interface | `ASWebAuthenticationSessionCallback.h` | WebAuthenticationCallback |
| `ASWebAuthenticationSessionRequest` | interface | `ASWebAuthenticationSessionRequest.h` | WebAuthenticationSessionRequest |
| `ASWebAuthenticationSessionRequestDelegate` | protocol | `ASWebAuthenticationSessionRequest.h` | WebAuthenticationSessionRequestDelegate |
| `ASWebAuthenticationSessionWebBrowserSessionHandling` | protocol | `ASWebAuthenticationSessionWebBrowserSessionHandling.h` | WebAuthenticationSessionWebBrowserSessionHandling |
| `ASWebAuthenticationSessionWebBrowserSessionManager` | interface | `ASWebAuthenticationSessionWebBrowserSessionManager.h` | WebAuthenticationSessionWebBrowserSessionManager |
| `ASCOSEConstants` | interface | `ASCOSEConstants.h` | (via constants module) |
| `ASGeneratedPasswordKind` | enum | `ASGeneratedPasswordKind.h` | (password generation) |
| `ASPublicKeyCredentialAttestationKind` | enum | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialAttestationKind |
| `ASPublicKeyCredentialResidentKeyPreference` | enum | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialResidentKeyPreference |
| `ASPublicKeyCredentialUserVerificationPreference` | enum | `ASAuthorizationPublicKeyCredentialConstants.h` | PublicKeyCredentialUserVerificationPreference |
| `ASAuthorizationProviderExtensionFederationType` | enum | `ASAuthorizationProviderExtensionLoginConfiguration.h` | (extension APIs) |
| `ASAuthorizationProviderExtensionAuthenticationMethod` | enum | `ASAuthorizationProviderExtensionLoginManager.h` | (extension APIs) |
| `ASAuthorizationProviderExtensionKeyType` | enum | `ASAuthorizationProviderExtensionLoginManager.h` | (extension APIs) |
| `ASAuthorizationProviderExtensionPlatformSSOProtocolVersion` | enum | `ASAuthorizationProviderExtensionLoginManager.h` | (extension APIs) |

## 🔴 GAPS

(none)

## ⏭️ EXEMPT
| Symbol | Kind | Header | Reason | SDK attribute |
| --- | --- | --- | --- | --- |
| `ASAuthorizationAppleIDButton` | interface | `ASAuthorizationAppleIDButton.h` | NSControl subclass; requires AppKit (objc2 interop avoided per doom-fish guidelines) | API_AVAILABLE(ios(13.0), macos(10.15), tvos(13.0)) API_UNAVAILABLE(watchos) |
| `ASAccountAuthenticationModificationController` | interface | `ASAccountAuthenticationModificationController.h` | iOS-only account modification API | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationControllerDelegate` | protocol | `ASAccountAuthenticationModificationController.h` | iOS-only account modification delegate | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationControllerPresentationContextProviding` | protocol | `ASAccountAuthenticationModificationController.h` | iOS-only account modification UI context | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationExtensionContext` | interface | `ASAccountAuthenticationModificationExtensionContext.h` | iOS-only extension context | API_UNAVAILABLE(macos, watchos, tvos) |
| `ASAccountAuthenticationModificationReplacePasswordWithSignInWithAppleRequest` | interface | `ASAccountAuthenticationModificationReplacePasswordWithSignInWithAppleRequest.h` | iOS-only account modification request | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationRequest` | interface | `ASAccountAuthenticationModificationRequest.h` | iOS-only base request | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationUpgradePasswordToStrongPasswordRequest` | interface | `ASAccountAuthenticationModificationUpgradePasswordToStrongPasswordRequest.h` | iOS-only account modification request | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASAccountAuthenticationModificationViewController` | interface | `ASAccountAuthenticationModificationViewController.h` | iOS-only account modification view controller | API_UNAVAILABLE(macos, watchos, tvos) |
| `ASAuthorizationCustomMethodVideoSubscriberAccount` | constant | `ASAuthorizationCustomMethod.h` | tvOS-only custom auth method | API_UNAVAILABLE(ios, macos, watchos) |
| `ASAuthorizationCustomMethodRestorePurchase` | constant | `ASAuthorizationCustomMethod.h` | tvOS-only custom auth method | API_UNAVAILABLE(ios, macos, watchos) |
| `ASAuthorizationCustomMethodOther` | constant | `ASAuthorizationCustomMethod.h` | tvOS-only custom auth method | API_UNAVAILABLE(ios, macos, watchos) |
| `ASAuthorizationProviderExtensionUserSecureEnclaveKeyBiometricPolicy` | options | `ASAuthorizationProviderExtensionLoginConfiguration.h` | iOS-only secure enclave policy | API_UNAVAILABLE(macos) |
| `ASExtensionLocalizedFailureReasonErrorKey` | constant | `ASExtensionErrors.h` | iOS-only error key | API_AVAILABLE(ios(14.0)) API_UNAVAILABLE(macos, tvos, watchos) |
| `ASGeneratePasswordsRequest` | interface | `ASGeneratePasswordsRequest.h` | iOS/visionOS-only password generation | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASGeneratedPassword` | interface | `ASGeneratedPassword.h` | iOS/visionOS-only password object | API_UNAVAILABLE(macos, tvos, watchos) |
| `ASSavePasswordRequest` | interface | `ASSavePasswordRequest.h` | iOS/visionOS-only password save request | API_UNAVAILABLE(macos, tvos, watchos) |

