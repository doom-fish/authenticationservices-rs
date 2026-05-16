import Foundation
import AuthenticationServices

final class ASAppleIDRequestHandle {
    let request: ASAuthorizationAppleIDRequest

    init(_ request: ASAuthorizationAppleIDRequest) {
        self.request = request
    }
}

private struct AuthServicesAppleIDRequestPayload: Codable {
    let requestedScopes: [String]
    let user: String?
    let state: String?
    let nonce: String?
    let requestedOperation: String?
}

private struct AuthServicesAppleIDCredentialStatePayload: Codable {
    let state: String
}

private func authservicesAppleIDScopeName(_ scope: ASAuthorization.Scope) -> String {
    switch scope {
    case .email:
        return "email"
    case .fullName:
        return "fullName"
    default:
        return "unknown"
    }
}

private func authservicesAppleIDScopes(_ scopeNames: [String]) -> [ASAuthorization.Scope] {
    scopeNames.compactMap { scopeName in
        switch scopeName {
        case "email":
            return .email
        case "fullName":
            return .fullName
        default:
            return nil
        }
    }
}

private func authservicesAppleIDOperationName(_ operation: ASAuthorization.OpenIDOperation) -> String {
    switch operation {
    case .operationImplicit:
        return "implicit"
    case .operationLogin:
        return "login"
    case .operationRefresh:
        return "refresh"
    case .operationLogout:
        return "logout"
    default:
        return "implicit"
    }
}

private func authservicesAppleIDOperation(_ name: String?) -> ASAuthorization.OpenIDOperation? {
    switch name {
    case .none:
        return nil
    case .some("implicit"):
        return .operationImplicit
    case .some("login"):
        return .operationLogin
    case .some("refresh"):
        return .operationRefresh
    case .some("logout"):
        return .operationLogout
    default:
        return nil
    }
}

private func authservicesBuildAppleIDRequestPayload(
    _ request: ASAuthorizationAppleIDRequest
) -> AuthServicesAppleIDRequestPayload {
    AuthServicesAppleIDRequestPayload(
        requestedScopes: (request.requestedScopes ?? []).map(authservicesAppleIDScopeName),
        user: request.user,
        state: request.state,
        nonce: request.nonce,
        requestedOperation: authservicesAppleIDOperationName(request.requestedOperation)
    )
}

private func authservicesApplyAppleIDRequestPayload(
    _ payload: AuthServicesAppleIDRequestPayload,
    to request: ASAuthorizationAppleIDRequest
) {
    request.requestedScopes = authservicesAppleIDScopes(payload.requestedScopes)
    request.user = payload.user
    request.state = payload.state
    request.nonce = payload.nonce
    if let requestedOperation = authservicesAppleIDOperation(payload.requestedOperation) {
        request.requestedOperation = requestedOperation
    }
}

private func authservicesAppleIDCredentialStateName(
    _ state: ASAuthorizationAppleIDProvider.CredentialState
) -> String {
    switch state {
    case .authorized:
        return "authorized"
    case .revoked:
        return "revoked"
    case .notFound:
        return "not_found"
    case .transferred:
        return "transferred"
    default:
        return "unknown"
    }
}

@_cdecl("authservices_apple_id_provider_create_request")
public func authservices_apple_id_provider_create_request(
    _ scopesJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        if let scopesJson {
            let scopes = try authservicesDecodeJSON(scopesJson, as: [String].self)
            request.requestedScopes = authservicesAppleIDScopes(scopes)
        } else {
            request.requestedScopes = [.fullName, .email]
        }
        return authservices_retain(ASAppleIDRequestHandle(request))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_apple_id_request_release")
public func authservices_apple_id_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_apple_id_request_kind_json")
public func authservices_apple_id_request_kind_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    _ = authservices_borrow(ptr, as: ASAppleIDRequestHandle.self)
    return authservicesCopyJSON(
        AuthServicesRequestKindPayload(
            kind: "apple_id",
            relyingPartyIdentifier: nil,
            challenge: nil,
            userID: nil,
            userName: nil,
            userDisplayName: nil
        )
    )
}

@_cdecl("authservices_apple_id_request_copy_json")
public func authservices_apple_id_request_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    let handle = authservices_borrow(ptr, as: ASAppleIDRequestHandle.self)
    return authservicesCopyJSON(authservicesBuildAppleIDRequestPayload(handle.request))
}

@_cdecl("authservices_apple_id_request_update_from_json")
public func authservices_apple_id_request_update_from_json(
    _ ptr: UnsafeMutableRawPointer?,
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null Apple ID request handle")
        )
    }
    do {
        let payload = try authservicesDecodeJSON(payloadJson, as: AuthServicesAppleIDRequestPayload.self)
        let handle = authservices_borrow(ptr, as: ASAppleIDRequestHandle.self)
        authservicesApplyAppleIDRequestPayload(payload, to: handle.request)
        return AUTHSERVICES_OK
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_apple_id_provider_credential_state_json")
public func authservices_apple_id_provider_credential_state_json(
    _ userID: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutablePointer<CChar>? {
    guard let userID else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("user_id is required")
        )
        return nil
    }
    let provider = ASAuthorizationAppleIDProvider()
    let userIDString = String(cString: userID)
    var stateJson: UnsafeMutablePointer<CChar>?
    let status = authservicesBlockOnAsync(
        work: {
            try await provider.credentialState(forUserID: userIDString)
        },
        onSuccess: { state in
            stateJson = authservicesCopyJSON(
                AuthServicesAppleIDCredentialStatePayload(
                    state: authservicesAppleIDCredentialStateName(state)
                )
            )
        },
        onError: { error in
            authservicesPopulateError(outError, with: error)
        }
    )
    return status == AUTHSERVICES_OK ? stateJson : nil
}

@_cdecl("authservices_apple_id_provider_credential_revoked_notification")
public func authservices_apple_id_provider_credential_revoked_notification() -> UnsafeMutablePointer<CChar>? {
    authservicesCString(ASAuthorizationAppleIDProvider.credentialRevokedNotification.rawValue)
}
