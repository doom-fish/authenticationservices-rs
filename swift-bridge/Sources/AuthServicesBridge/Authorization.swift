import AppKit
import Foundation
import AuthenticationServices

final class AuthControllerDelegate: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding {

    typealias SuccessFn = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void
    typealias ErrorFn = @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void

    let refcon: UnsafeMutableRawPointer?
    let onSuccess: SuccessFn
    let onError: ErrorFn

    init(refcon: UnsafeMutableRawPointer?, onSuccess: @escaping SuccessFn, onError: @escaping ErrorFn) {
        self.refcon = refcon
        self.onSuccess = onSuccess
        self.onError = onError
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        if let window = NSApplication.shared.windows.first {
            return window
        }
        return NSWindow()
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        onSuccess(refcon, authservicesCopyJSON(buildAuthorizationPayload(from: authorization)))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        onError(refcon, authservicesStatus(for: error), authservicesCString(error.localizedDescription))
    }
}

final class AuthControllerHandle {
    let controller: ASAuthorizationController
    let delegate: AuthControllerDelegate

    init(controller: ASAuthorizationController, delegate: AuthControllerDelegate) {
        self.controller = controller
        self.delegate = delegate
    }
}

@available(macOS 15.0, *)
private func authservicesPRFRegistrationParts(
    _ output: ASAuthorizationPublicKeyCredentialPRFRegistrationOutput?
) -> (String?, String?, Bool?) {
    guard let output else { return (nil, nil, nil) }
    return (
        authservicesSymmetricKeyBase64(output.first),
        authservicesSymmetricKeyBase64(output.second),
        output.isSupported
    )
}

private func buildAuthorizationPayload(from authorization: ASAuthorization) -> AuthServicesAuthorizationPayload {
    if let credential = authorization.credential as? ASAuthorizationAppleIDCredential {
        let fullName = credential.fullName.map {
            [$0.givenName, $0.familyName].compactMap { $0 }.joined(separator: " ")
        }
        return AuthServicesAuthorizationPayload(
            provider: "apple_id",
            userIdentifier: credential.user,
            email: credential.email,
            fullName: fullName,
            identityToken: credential.identityToken?.base64EncodedString(),
            authorizationCode: credential.authorizationCode?.base64EncodedString(),
            password: nil,
            credentialID: nil,
            rawAttestationObject: nil,
            rawAuthenticatorData: nil,
            signature: nil,
            userID: nil,
            attachment: nil,
            usedAppID: nil,
            transports: nil,
            largeBlobResultKind: nil,
            largeBlobData: nil,
            largeBlobWriteSucceeded: nil,
            largeBlobSupported: nil,
            prfFirst: nil,
            prfSecond: nil,
            prfSupported: nil,
            error: nil
        )
    }
    if let credential = authorization.credential as? ASPasswordCredential {
        return AuthServicesAuthorizationPayload(
            provider: "password",
            userIdentifier: credential.user,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            password: credential.password,
            credentialID: nil,
            rawAttestationObject: nil,
            rawAuthenticatorData: nil,
            signature: nil,
            userID: nil,
            attachment: nil,
            usedAppID: nil,
            transports: nil,
            largeBlobResultKind: nil,
            largeBlobData: nil,
            largeBlobWriteSucceeded: nil,
            largeBlobSupported: nil,
            prfFirst: nil,
            prfSecond: nil,
            prfSupported: nil,
            error: nil
        )
    }
    if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
        let attachment: Int?
        if #available(macOS 13.5, *) {
            attachment = authservicesAttachmentRawValue(credential.attachment)
        } else {
            attachment = nil
        }
        let largeBlobSupported: Bool?
        if #available(macOS 14.0, *) {
            largeBlobSupported = credential.largeBlob?.isSupported
        } else {
            largeBlobSupported = nil
        }
        let prf: (String?, String?, Bool?)
        if #available(macOS 15.0, *) {
            prf = authservicesPRFRegistrationParts(credential.prf)
        } else {
            prf = (nil, nil, nil)
        }
        return AuthServicesAuthorizationPayload(
            provider: "platform_passkey_registration",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            password: nil,
            credentialID: credential.credentialID.base64EncodedString(),
            rawAttestationObject: credential.rawAttestationObject?.base64EncodedString(),
            rawAuthenticatorData: nil,
            signature: nil,
            userID: nil,
            attachment: attachment,
            usedAppID: nil,
            transports: nil,
            largeBlobResultKind: nil,
            largeBlobData: nil,
            largeBlobWriteSucceeded: nil,
            largeBlobSupported: largeBlobSupported,
            prfFirst: prf.0,
            prfSecond: prf.1,
            prfSupported: prf.2,
            error: nil
        )
    }
    if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
        let attachment: Int?
        if #available(macOS 13.5, *) {
            attachment = authservicesAttachmentRawValue(credential.attachment)
        } else {
            attachment = nil
        }
        let largeBlob: (String?, String?, Bool?)
        if #available(macOS 14.0, *) {
            largeBlob = authservicesLargeBlobAssertionOutputPayloadIfAvailable(credential.largeBlob)
        } else {
            largeBlob = (nil, nil, nil)
        }
        let prf: (String?, String?)
        if #available(macOS 15.0, *) {
            prf = authservicesPRFOutputPayloadIfAvailable(credential.prf)
        } else {
            prf = (nil, nil)
        }
        return AuthServicesAuthorizationPayload(
            provider: "platform_passkey_assertion",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            password: nil,
            credentialID: credential.credentialID.base64EncodedString(),
            rawAttestationObject: nil,
            rawAuthenticatorData: credential.rawAuthenticatorData.base64EncodedString(),
            signature: credential.signature.base64EncodedString(),
            userID: credential.userID.base64EncodedString(),
            attachment: attachment,
            usedAppID: nil,
            transports: nil,
            largeBlobResultKind: largeBlob.0,
            largeBlobData: largeBlob.1,
            largeBlobWriteSucceeded: largeBlob.2,
            largeBlobSupported: nil,
            prfFirst: prf.0,
            prfSecond: prf.1,
            prfSupported: nil,
            error: nil
        )
    }
    if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
        let transports: [String]?
        if #available(macOS 14.5, *) {
            transports = credential.transports.map(authservicesSecurityTransportName)
        } else {
            transports = nil
        }
        return AuthServicesAuthorizationPayload(
            provider: "security_key_passkey_registration",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            password: nil,
            credentialID: credential.credentialID.base64EncodedString(),
            rawAttestationObject: credential.rawAttestationObject?.base64EncodedString(),
            rawAuthenticatorData: nil,
            signature: nil,
            userID: nil,
            attachment: nil,
            usedAppID: nil,
            transports: transports,
            largeBlobResultKind: nil,
            largeBlobData: nil,
            largeBlobWriteSucceeded: nil,
            largeBlobSupported: nil,
            prfFirst: nil,
            prfSecond: nil,
            prfSupported: nil,
            error: nil
        )
    }
    if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
        let usedAppID: Bool?
        if #available(macOS 14.5, *) {
            usedAppID = credential.appID
        } else {
            usedAppID = nil
        }
        return AuthServicesAuthorizationPayload(
            provider: "security_key_passkey_assertion",
            userIdentifier: nil,
            email: nil,
            fullName: nil,
            identityToken: nil,
            authorizationCode: nil,
            password: nil,
            credentialID: credential.credentialID.base64EncodedString(),
            rawAttestationObject: nil,
            rawAuthenticatorData: credential.rawAuthenticatorData.base64EncodedString(),
            signature: credential.signature.base64EncodedString(),
            userID: credential.userID.base64EncodedString(),
            attachment: nil,
            usedAppID: usedAppID,
            transports: nil,
            largeBlobResultKind: nil,
            largeBlobData: nil,
            largeBlobWriteSucceeded: nil,
            largeBlobSupported: nil,
            prfFirst: nil,
            prfSecond: nil,
            prfSupported: nil,
            error: nil
        )
    }
    return AuthServicesAuthorizationPayload(
        provider: "unknown",
        userIdentifier: nil,
        email: nil,
        fullName: nil,
        identityToken: nil,
        authorizationCode: nil,
        password: nil,
        credentialID: nil,
        rawAttestationObject: nil,
        rawAuthenticatorData: nil,
        signature: nil,
        userID: nil,
        attachment: nil,
        usedAppID: nil,
        transports: nil,
        largeBlobResultKind: nil,
        largeBlobData: nil,
        largeBlobWriteSucceeded: nil,
        largeBlobSupported: nil,
        prfFirst: nil,
        prfSecond: nil,
        prfSupported: nil,
        error: nil
    )
}

private func authservicesCreateController(
    appleIDRequest: UnsafeMutableRawPointer?,
    passwordRequest: UnsafeMutableRawPointer?,
    passkeyRegistrationRequest: UnsafeMutableRawPointer?,
    passkeyAssertionRequest: UnsafeMutableRawPointer?,
    securityKeyRegistrationRequest: UnsafeMutableRawPointer?,
    securityKeyAssertionRequest: UnsafeMutableRawPointer?,
    refcon: UnsafeMutableRawPointer?,
    onSuccess: @escaping @convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void,
    onError: @escaping @convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void,
    outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    var requests: [ASAuthorizationRequest] = []
    if let appleIDRequest {
        requests.append(authservices_borrow(appleIDRequest, as: ASAppleIDRequestHandle.self).request)
    }
    if let passwordRequest {
        requests.append(authservices_borrow(passwordRequest, as: ASPasswordRequestHandle.self).request)
    }
    if let passkeyRegistrationRequest {
        requests.append(authservices_borrow(passkeyRegistrationRequest, as: ASPasskeyRegistrationRequestHandle.self).request)
    }
    if let passkeyAssertionRequest {
        requests.append(authservices_borrow(passkeyAssertionRequest, as: ASPasskeyAssertionRequestHandle.self).request)
    }
    if let securityKeyRegistrationRequest {
        requests.append(authservices_borrow(securityKeyRegistrationRequest, as: ASSecurityKeyRegistrationRequestHandle.self).request)
    }
    if let securityKeyAssertionRequest {
        requests.append(authservices_borrow(securityKeyAssertionRequest, as: ASSecurityKeyAssertionRequestHandle.self).request)
    }
    guard !requests.isEmpty else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("at least one authorization request is required")
        )
        return nil
    }
    let delegate = AuthControllerDelegate(refcon: refcon, onSuccess: onSuccess, onError: onError)
    let controller = ASAuthorizationController(authorizationRequests: requests)
    controller.delegate = delegate
    controller.presentationContextProvider = delegate
    return authservices_retain(AuthControllerHandle(controller: controller, delegate: delegate))
}

@_cdecl("authservices_authorization_controller_create")
public func authservices_authorization_controller_create(
    _ appleIDRequest: UnsafeMutableRawPointer?,
    _ passwordRequest: UnsafeMutableRawPointer?,
    _ passkeyRegistrationRequest: UnsafeMutableRawPointer?,
    _ passkeyAssertionRequest: UnsafeMutableRawPointer?,
    _ refcon: UnsafeMutableRawPointer?,
    _ onSuccess: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void)?,
    _ onError: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void)?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard let onSuccess, let onError else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("authorization controller callbacks are required")
        )
        return nil
    }
    return authservicesCreateController(
        appleIDRequest: appleIDRequest,
        passwordRequest: passwordRequest,
        passkeyRegistrationRequest: passkeyRegistrationRequest,
        passkeyAssertionRequest: passkeyAssertionRequest,
        securityKeyRegistrationRequest: nil,
        securityKeyAssertionRequest: nil,
        refcon: refcon,
        onSuccess: onSuccess,
        onError: onError,
        outError: outError
    )
}

@_cdecl("authservices_authorization_controller_create_v2")
public func authservices_authorization_controller_create_v2(
    _ appleIDRequest: UnsafeMutableRawPointer?,
    _ passwordRequest: UnsafeMutableRawPointer?,
    _ passkeyRegistrationRequest: UnsafeMutableRawPointer?,
    _ passkeyAssertionRequest: UnsafeMutableRawPointer?,
    _ securityKeyRegistrationRequest: UnsafeMutableRawPointer?,
    _ securityKeyAssertionRequest: UnsafeMutableRawPointer?,
    _ refcon: UnsafeMutableRawPointer?,
    _ onSuccess: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?) -> Void)?,
    _ onError: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<CChar>?) -> Void)?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard let onSuccess, let onError else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("authorization controller callbacks are required")
        )
        return nil
    }
    return authservicesCreateController(
        appleIDRequest: appleIDRequest,
        passwordRequest: passwordRequest,
        passkeyRegistrationRequest: passkeyRegistrationRequest,
        passkeyAssertionRequest: passkeyAssertionRequest,
        securityKeyRegistrationRequest: securityKeyRegistrationRequest,
        securityKeyAssertionRequest: securityKeyAssertionRequest,
        refcon: refcon,
        onSuccess: onSuccess,
        onError: onError,
        outError: outError
    )
}

@_cdecl("authservices_authorization_controller_perform_requests")
public func authservices_authorization_controller_perform_requests(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    let handle = authservices_borrow(ptr, as: AuthControllerHandle.self)
    DispatchQueue.main.async {
        handle.controller.performRequests()
    }
}

@_cdecl("authservices_authorization_controller_perform_requests_with_options")
public func authservices_authorization_controller_perform_requests_with_options(
    _ ptr: UnsafeMutableRawPointer?,
    _ rawValue: UInt64,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null authorization controller handle")
        )
    }
    let handle = authservices_borrow(ptr, as: AuthControllerHandle.self)
    if rawValue == 0 {
        authservices_authorization_controller_perform_requests(ptr)
        return AUTHSERVICES_OK
    }
    guard #available(macOS 13.0, *) else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.notSupported(
                "ASAuthorizationController.performRequests(options:) requires macOS 13.0"
            )
        )
    }
    let options = ASAuthorizationController.RequestOptions(rawValue: UInt(rawValue))
    DispatchQueue.main.async {
        handle.controller.performRequests(options: options)
    }
    return AUTHSERVICES_OK
}

@_cdecl("authservices_authorization_controller_cancel")
public func authservices_authorization_controller_cancel(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    let handle = authservices_borrow(ptr, as: AuthControllerHandle.self)
    guard #available(macOS 13.0, *) else { return }
    DispatchQueue.main.async {
        handle.controller.cancel()
    }
}

@_cdecl("authservices_authorization_controller_request_count")
public func authservices_authorization_controller_request_count(_ ptr: UnsafeMutableRawPointer?) -> UInt64 {
    guard let ptr else { return 0 }
    let handle = authservices_borrow(ptr, as: AuthControllerHandle.self)
    return UInt64(handle.controller.authorizationRequests.count)
}

@_cdecl("authservices_authorization_controller_release")
public func authservices_authorization_controller_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}
