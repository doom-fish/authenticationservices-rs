import Foundation

private let authservicesAccountAuthenticationModificationNotSupportedReason =
    "ASAccountAuthenticationModificationController is unavailable on macOS"

@_cdecl("authservices_account_authentication_modification_controller_is_supported")
public func authservices_account_authentication_modification_controller_is_supported() -> Int32 {
    0
}

@_cdecl("authservices_account_authentication_modification_controller_reason")
public func authservices_account_authentication_modification_controller_reason() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(authservicesAccountAuthenticationModificationNotSupportedReason)
}

@_cdecl("authservices_account_authentication_modification_controller_perform_stub")
public func authservices_account_authentication_modification_controller_perform_stub(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    authservicesFail(
        outError,
        with: AuthServicesBridgeError.notSupported(
            authservicesAccountAuthenticationModificationNotSupportedReason
        )
    )
}
