import Foundation
import AuthenticationServices

final class ASPasswordCredentialHandle {
    let credential: ASPasswordCredential

    init(_ credential: ASPasswordCredential) {
        self.credential = credential
    }
}

private struct AuthServicesPasswordCredentialPayload: Codable {
    let user: String
    let password: String
}

@_cdecl("authservices_password_credential_create")
public func authservices_password_credential_create(
    _ user: UnsafePointer<CChar>?,
    _ password: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard let user, let password else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("user and password are required")
        )
        return nil
    }
    let credential = ASPasswordCredential(
        user: String(cString: user),
        password: String(cString: password)
    )
    return authservices_retain(ASPasswordCredentialHandle(credential))
}

@_cdecl("authservices_password_credential_copy_json")
public func authservices_password_credential_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    let handle = authservices_borrow(ptr, as: ASPasswordCredentialHandle.self)
    return authservicesCopyJSON(
        AuthServicesPasswordCredentialPayload(
            user: handle.credential.user,
            password: handle.credential.password
        )
    )
}

@_cdecl("authservices_password_credential_release")
public func authservices_password_credential_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}
