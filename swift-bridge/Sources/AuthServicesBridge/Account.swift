import Foundation

private let authservicesAccountNotSupportedReason =
    "ASAccount request-family APIs are unavailable in AuthenticationServices on macOS"

@_cdecl("authservices_account_request_family_is_supported")
public func authservices_account_request_family_is_supported() -> Int32 {
    0
}

@_cdecl("authservices_account_request_family_reason")
public func authservices_account_request_family_reason() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(authservicesAccountNotSupportedReason)
}
