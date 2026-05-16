import Foundation
import AuthenticationServices

final class ASPasswordRequestHandle {
    let request: ASAuthorizationPasswordRequest

    init(_ request: ASAuthorizationPasswordRequest) {
        self.request = request
    }
}

private struct AuthServicesProviderDescriptorPayload: Codable {
    let protocolName: String
    let supportedKinds: [String]
}

@_cdecl("authservices_password_provider_create_request")
public func authservices_password_provider_create_request(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    _ = outError
    let provider = ASAuthorizationPasswordProvider()
    let request = provider.createRequest()
    return authservices_retain(ASPasswordRequestHandle(request))
}

@_cdecl("authservices_password_request_release")
public func authservices_password_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_password_request_kind_json")
public func authservices_password_request_kind_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    _ = authservices_borrow(ptr, as: ASPasswordRequestHandle.self)
    return authservicesCopyJSON(
        AuthServicesRequestKindPayload(
            kind: "password",
            relyingPartyIdentifier: nil,
            challenge: nil,
            userID: nil,
            userName: nil,
            userDisplayName: nil
        )
    )
}

@_cdecl("authservices_authorization_provider_protocol_name")
public func authservices_authorization_provider_protocol_name() -> UnsafeMutablePointer<CChar>? {
    authservicesCString("ASAuthorizationProvider")
}

@_cdecl("authservices_authorization_provider_supported_kinds_json")
public func authservices_authorization_provider_supported_kinds_json() -> UnsafeMutablePointer<CChar>? {
    authservicesCopyJSON(
        AuthServicesProviderDescriptorPayload(
            protocolName: "ASAuthorizationProvider",
            supportedKinds: [
                "apple_id",
                "password",
                "platform_public_key_credential",
                "security_key_public_key_credential"
            ]
        )
    )
}
