import AppKit
import Foundation
import AuthenticationServices

// MARK: – Request-handle types

/// Opaque handle for an ASAuthorizationAppleIDRequest
final class ASAppleIDRequestHandle {
    let request: ASAuthorizationAppleIDRequest
    init(_ request: ASAuthorizationAppleIDRequest) { self.request = request }
}

/// Opaque handle for an ASAuthorizationPasswordRequest
final class ASPasswordRequestHandle {
    let request: ASAuthorizationPasswordRequest
    init(_ request: ASAuthorizationPasswordRequest) { self.request = request }
}

/// Opaque handle for a platform passkey registration request
final class ASPasskeyRegistrationRequestHandle {
    let request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest
    init(_ request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest) { self.request = request }
}

/// Opaque handle for a platform passkey assertion request
final class ASPasskeyAssertionRequestHandle {
    let request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
    init(_ request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest) { self.request = request }
}

// MARK: – AppleID provider

@_cdecl("authservices_apple_id_provider_create_request")
public func authservices_apple_id_provider_create_request(
    scopes_json: UnsafePointer<CChar>?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        if let scopesJson = scopes_json {
            let scopeStrings = try authservicesDecodeJSON(scopesJson, as: [String].self)
            request.requestedScopes = scopeStrings.compactMap { s -> ASAuthorization.Scope? in
                switch s {
                case "fullName": return .fullName
                case "email":    return .email
                default:           return nil
                }
            }
        } else {
            request.requestedScopes = [.fullName, .email]
        }
        let handle = ASAppleIDRequestHandle(request)
        return authservices_retain(handle)
    } catch {
        authservicesPopulateError(out_error, with: error)
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
    let payload = AuthServicesRequestKindPayload(
        kind: "apple_id",
        relyingPartyIdentifier: nil,
        challenge: nil,
        userID: nil,
        userName: nil,
        userDisplayName: nil
    )
    return (try? authservicesEncodeJSON(payload)).flatMap { authservicesCString($0) }
}

// MARK: – Password provider

@_cdecl("authservices_password_provider_create_request")
public func authservices_password_provider_create_request(
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    _ = out_error
    let provider = ASAuthorizationPasswordProvider()
    let request = provider.createRequest()
    let handle = ASPasswordRequestHandle(request)
    return authservices_retain(handle)
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
    let payload = AuthServicesRequestKindPayload(
        kind: "password",
        relyingPartyIdentifier: nil,
        challenge: nil,
        userID: nil,
        userName: nil,
        userDisplayName: nil
    )
    return (try? authservicesEncodeJSON(payload)).flatMap { authservicesCString($0) }
}

// MARK: – Passkey platform provider

@_cdecl("authservices_passkey_registration_request_create")
public func authservices_passkey_registration_request_create(
    relying_party_id: UnsafePointer<CChar>?,
    challenge_b64: UnsafePointer<CChar>?,
    user_id_b64: UnsafePointer<CChar>?,
    user_name: UnsafePointer<CChar>?,
    user_display_name: UnsafePointer<CChar>?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard
        let rpId = relying_party_id.map({ String(cString: $0) }),
        let challengeB64 = challenge_b64.map({ String(cString: $0) }),
        let userIdB64 = user_id_b64.map({ String(cString: $0) }),
        let challengeData = Data(base64Encoded: challengeB64, options: .ignoreUnknownCharacters),
        let userIdData = Data(base64Encoded: userIdB64, options: .ignoreUnknownCharacters)
    else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument(
            "relying_party_id, challenge_b64, and user_id_b64 are required and must be valid base64"
        ))
        return nil
    }
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
    let displayName = user_display_name.map { String(cString: $0) } ?? user_name.map { String(cString: $0) } ?? ""
    let request = provider.createCredentialRegistrationRequest(
        challenge: challengeData,
        name: user_name.map { String(cString: $0) } ?? "",
        userID: userIdData
    )
    request.displayName = displayName
    let handle = ASPasskeyRegistrationRequestHandle(request)
    return authservices_retain(handle)
}

@_cdecl("authservices_passkey_registration_request_release")
public func authservices_passkey_registration_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_passkey_registration_request_kind_json")
public func authservices_passkey_registration_request_kind_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    let handle = authservices_borrow(ptr, as: ASPasskeyRegistrationRequestHandle.self)
    let rpId = handle.request.relyingPartyIdentifier
    let payload = AuthServicesRequestKindPayload(
        kind: "passkey_registration",
        relyingPartyIdentifier: rpId,
        challenge: handle.request.challenge.base64EncodedString(),
        userID: handle.request.userID.base64EncodedString(),
        userName: handle.request.name,
        userDisplayName: handle.request.displayName
    )
    return (try? authservicesEncodeJSON(payload)).flatMap { authservicesCString($0) }
}

@_cdecl("authservices_passkey_assertion_request_create")
public func authservices_passkey_assertion_request_create(
    relying_party_id: UnsafePointer<CChar>?,
    challenge_b64: UnsafePointer<CChar>?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard
        let rpId = relying_party_id.map({ String(cString: $0) }),
        let challengeB64 = challenge_b64.map({ String(cString: $0) }),
        let challengeData = Data(base64Encoded: challengeB64, options: .ignoreUnknownCharacters)
    else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument(
            "relying_party_id and challenge_b64 are required"
        ))
        return nil
    }
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
    let request = provider.createCredentialAssertionRequest(challenge: challengeData)
    let handle = ASPasskeyAssertionRequestHandle(request)
    return authservices_retain(handle)
}

@_cdecl("authservices_passkey_assertion_request_release")
public func authservices_passkey_assertion_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_passkey_assertion_request_kind_json")
public func authservices_passkey_assertion_request_kind_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    let handle = authservices_borrow(ptr, as: ASPasskeyAssertionRequestHandle.self)
    let rpId = handle.request.relyingPartyIdentifier
    let payload = AuthServicesRequestKindPayload(
        kind: "passkey_assertion",
        relyingPartyIdentifier: rpId,
        challenge: handle.request.challenge.base64EncodedString(),
        userID: nil,
        userName: nil,
        userDisplayName: nil
    )
    return (try? authservicesEncodeJSON(payload)).flatMap { authservicesCString($0) }
}

// MARK: – AuthorizationController

/// NSObject delegate that bridges ASAuthorizationController callbacks → Rust fn ptrs.
final class AuthControllerDelegate: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding {

    typealias SuccessFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void
    typealias ErrorFn   = @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void

    let refcon: UnsafeMutableRawPointer?
    let onSuccess: SuccessFn
    let onError: ErrorFn

    init(refcon: UnsafeMutableRawPointer?, onSuccess: @escaping SuccessFn, onError: @escaping ErrorFn) {
        self.refcon    = refcon
        self.onSuccess = onSuccess
        self.onError   = onError
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        if let window = NSApplication.shared.windows.first { return window }
        return NSWindow()
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        let payload = buildAuthorizationPayload(from: authorization)
        let json = (try? authservicesEncodeJSON(payload)) ?? "{}"
        onSuccess(refcon, authservicesCString(json))
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let nsErr = error as NSError
        let msg = nsErr.localizedDescription
        let code = authservicesStatus(for: error)
        onError(refcon, code, authservicesCString(msg))
    }
}

private func buildAuthorizationPayload(from authorization: ASAuthorization) -> AuthServicesAuthorizationPayload {
    if let cred = authorization.credential as? ASAuthorizationAppleIDCredential {
        let nameComponents = cred.fullName
        let fullName: String? = nameComponents.map { nc in
            [nc.givenName, nc.familyName].compactMap { $0 }.joined(separator: " ")
        }
        return AuthServicesAuthorizationPayload(
            provider: "apple_id",
            userIdentifier: cred.user,
            email: cred.email,
            fullName: fullName,
            identityToken: cred.identityToken.map { $0.base64EncodedString() },
            authorizationCode: cred.authorizationCode.map { $0.base64EncodedString() },
            credentialID: nil,
            rawAttestationObject: nil,
            rawAuthenticatorData: nil,
            signature: nil,
            error: nil
        )
    } else if let cred = authorization.credential as? ASPasswordCredential {
        return AuthServicesAuthorizationPayload(
            provider: "password",
            userIdentifier: cred.user,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            credentialID: nil,
            rawAttestationObject: nil,
            rawAuthenticatorData: nil,
            signature: nil,
            error: nil
        )
    } else if let cred = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
        return AuthServicesAuthorizationPayload(
            provider: "passkey_registration",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            credentialID: cred.credentialID.base64EncodedString(),
            rawAttestationObject: cred.rawAttestationObject?.base64EncodedString(),
            rawAuthenticatorData: nil,
            signature: nil,
            error: nil
        )
    } else if let cred = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
        return AuthServicesAuthorizationPayload(
            provider: "passkey_assertion",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            credentialID: cred.credentialID.base64EncodedString(),
            rawAttestationObject: nil,
            rawAuthenticatorData: cred.rawAuthenticatorData.base64EncodedString(),
            signature: cred.signature.base64EncodedString(),
            error: nil
        )
    } else {
        return AuthServicesAuthorizationPayload(
            provider: "unknown",
            userIdentifier: nil, email: nil, fullName: nil,
            identityToken: nil, authorizationCode: nil,
            credentialID: nil, rawAttestationObject: nil,
            rawAuthenticatorData: nil, signature: nil, error: nil
        )
    }
}

/// Opaque handle that keeps both the controller and its delegate alive.
final class AuthControllerHandle {
    let controller: ASAuthorizationController
    let delegate: AuthControllerDelegate
    init(controller: ASAuthorizationController, delegate: AuthControllerDelegate) {
        self.controller = controller
        self.delegate   = delegate
    }
}

@_cdecl("authservices_authorization_controller_create")
public func authservices_authorization_controller_create(
    apple_id_request: UnsafeMutableRawPointer?,
    password_request: UnsafeMutableRawPointer?,
    passkey_reg_request: UnsafeMutableRawPointer?,
    passkey_assert_request: UnsafeMutableRawPointer?,
    refcon: UnsafeMutableRawPointer?,
    on_success: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void)?,
    on_error: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void)?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    var requests: [ASAuthorizationRequest] = []
    if let ptr = apple_id_request {
        requests.append(authservices_borrow(ptr, as: ASAppleIDRequestHandle.self).request)
    }
    if let ptr = password_request {
        requests.append(authservices_borrow(ptr, as: ASPasswordRequestHandle.self).request)
    }
    if let ptr = passkey_reg_request {
        requests.append(authservices_borrow(ptr, as: ASPasskeyRegistrationRequestHandle.self).request)
    }
    if let ptr = passkey_assert_request {
        requests.append(authservices_borrow(ptr, as: ASPasskeyAssertionRequestHandle.self).request)
    }
    guard !requests.isEmpty else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument("at least one request is required"))
        return nil
    }
    guard let onSuccess = on_success, let onError = on_error else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument("callbacks are required"))
        return nil
    }
    let delegate = AuthControllerDelegate(refcon: refcon, onSuccess: onSuccess, onError: onError)
    let controller = ASAuthorizationController(authorizationRequests: requests)
    controller.delegate = delegate
    controller.presentationContextProvider = delegate
    let handle = AuthControllerHandle(controller: controller, delegate: delegate)
    return authservices_retain(handle)
}

@_cdecl("authservices_authorization_controller_perform_requests")
public func authservices_authorization_controller_perform_requests(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    let handle = authservices_borrow(ptr, as: AuthControllerHandle.self)
    DispatchQueue.main.async {
        handle.controller.performRequests()
    }
}

@_cdecl("authservices_authorization_controller_release")
public func authservices_authorization_controller_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}
