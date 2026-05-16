import Foundation
import AuthenticationServices

private struct AuthServicesCredentialIdentityStoreStatePayload: Codable {
    let isEnabled: Bool
    let supportsIncrementalUpdates: Bool
}

private let authservicesCredentialIdentityStoreUnsupportedReason =
    "credential identity mutation/listing APIs are not bridged yet; state() is available"

@_cdecl("authservices_credential_identity_store_is_supported")
public func authservices_credential_identity_store_is_supported() -> Int32 {
    1
}

@_cdecl("authservices_credential_identity_store_state_json")
public func authservices_credential_identity_store_state_json(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutablePointer<CChar>? {
    var payloadJson: UnsafeMutablePointer<CChar>?
    let status = authservicesBlockOnAsync(
        work: {
            try await ASCredentialIdentityStore.shared.state()
        },
        onSuccess: { state in
            payloadJson = authservicesCopyJSON(
                AuthServicesCredentialIdentityStoreStatePayload(
                    isEnabled: state.isEnabled,
                    supportsIncrementalUpdates: state.supportsIncrementalUpdates
                )
            )
        },
        onError: { error in
            authservicesPopulateError(outError, with: error)
        }
    )
    return status == AUTHSERVICES_OK ? payloadJson : nil
}

private func authservicesCredentialIdentityStoreNotSupported(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    authservicesFail(
        outError,
        with: AuthServicesBridgeError.notSupported(authservicesCredentialIdentityStoreUnsupportedReason)
    )
}

@_cdecl("authservices_credential_identity_store_save_identities_json")
public func authservices_credential_identity_store_save_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    _ = payloadJson
    return authservicesCredentialIdentityStoreNotSupported(outError)
}

@_cdecl("authservices_credential_identity_store_remove_identities_json")
public func authservices_credential_identity_store_remove_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    _ = payloadJson
    return authservicesCredentialIdentityStoreNotSupported(outError)
}

@_cdecl("authservices_credential_identity_store_replace_identities_json")
public func authservices_credential_identity_store_replace_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    _ = payloadJson
    return authservicesCredentialIdentityStoreNotSupported(outError)
}

@_cdecl("authservices_credential_identity_store_remove_all")
public func authservices_credential_identity_store_remove_all(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    authservicesCredentialIdentityStoreNotSupported(outError)
}

@_cdecl("authservices_credential_identity_store_identities_json")
public func authservices_credential_identity_store_identities_json(
    _ servicePayloadJson: UnsafePointer<CChar>?,
    _ identityTypesRawValue: UInt64,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutablePointer<CChar>? {
    _ = servicePayloadJson
    _ = identityTypesRawValue
    authservicesPopulateError(
        outError,
        with: AuthServicesBridgeError.notSupported(authservicesCredentialIdentityStoreUnsupportedReason)
    )
    return nil
}
