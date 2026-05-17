import Foundation
import AuthenticationServices

@_cdecl("authservices_authorization_error_domain")
public func authservices_authorization_error_domain() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(ASAuthorizationErrorDomain)
}

@_cdecl("authservices_credential_identity_store_error_domain")
public func authservices_credential_identity_store_error_domain() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(ASCredentialIdentityStoreErrorDomain)
}

@_cdecl("authservices_extension_error_domain")
public func authservices_extension_error_domain() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(ASExtensionErrorDomain)
}

@_cdecl("authservices_web_authentication_session_error_domain")
public func authservices_web_authentication_session_error_domain() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(ASWebAuthenticationSessionErrorDomain)
}
