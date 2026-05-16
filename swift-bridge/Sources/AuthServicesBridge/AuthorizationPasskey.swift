import CryptoKit
import Foundation
import AuthenticationServices

private func authservicesUnsupportedClientData() -> AuthServicesBridgeError {
    AuthServicesBridgeError.notSupported("ASPublicKeyCredentialClientData is not yet bridged in authenticationservices-rs")
}

@available(macOS 15.0, *)
func authservicesSymmetricKeyBase64(_ key: SymmetricKey?) -> String? {
    guard let key else { return nil }
    return key.withUnsafeBytes { Data($0).base64EncodedString() }
}

final class ASPasskeyRegistrationRequestHandle {
    let request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest

    init(_ request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest) {
        self.request = request
    }
}

final class ASPasskeyAssertionRequestHandle {
    let request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest

    init(_ request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest) {
        self.request = request
    }
}

final class ASSecurityKeyRegistrationRequestHandle {
    let request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest

    init(_ request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest) {
        self.request = request
    }
}

final class ASSecurityKeyAssertionRequestHandle {
    let request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest

    init(_ request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest) {
        self.request = request
    }
}

final class ASPlatformCredentialDescriptorHandle {
    let descriptor: ASAuthorizationPlatformPublicKeyCredentialDescriptor

    init(_ descriptor: ASAuthorizationPlatformPublicKeyCredentialDescriptor) {
        self.descriptor = descriptor
    }
}

final class ASSecurityKeyCredentialDescriptorHandle {
    let descriptor: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor

    init(_ descriptor: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor) {
        self.descriptor = descriptor
    }
}

struct AuthServicesPlatformCredentialDescriptorPayload: Codable {
    let credentialID: String
}

struct AuthServicesSecurityKeyCredentialDescriptorPayload: Codable {
    let credentialID: String
    let transports: [String]?
}

private struct AuthServicesPRFInputValuesPayload: Codable {
    let saltInput1: String
    let saltInput2: String?
}

private struct AuthServicesPRFAssertionPerCredentialInputPayload: Codable {
    let credentialID: String
    let inputValues: AuthServicesPRFInputValuesPayload
}

private struct AuthServicesPRFAssertionInputPayload: Codable {
    let inputValues: AuthServicesPRFInputValuesPayload?
    let perCredentialInputValues: [AuthServicesPRFAssertionPerCredentialInputPayload]?
}

private struct AuthServicesLargeBlobRegistrationInputPayload: Codable {
    let supportRequirement: String
}

private struct AuthServicesLargeBlobAssertionInputPayload: Codable {
    let operation: String
    let data: String?
}

private struct AuthServicesPlatformRegistrationRequestPayload: Codable {
    let relyingPartyIdentifier: String
    let challenge: String?
    let clientData: String?
    let userID: String
    let name: String
    let displayName: String?
    let requestStyle: String?
    let userVerificationPreference: String?
    let attestationPreference: String?
    let largeBlob: AuthServicesLargeBlobRegistrationInputPayload?
    let prf: AuthServicesPRFInputValuesPayload?
    let prfShouldCheckForSupport: Bool?
}

private struct AuthServicesPlatformAssertionRequestPayload: Codable {
    let relyingPartyIdentifier: String
    let challenge: String?
    let clientData: String?
    let allowedCredentials: [AuthServicesPlatformCredentialDescriptorPayload]?
    let userVerificationPreference: String?
    let largeBlob: AuthServicesLargeBlobAssertionInputPayload?
    let prf: AuthServicesPRFAssertionInputPayload?
}

private struct AuthServicesSecurityKeyRegistrationRequestPayload: Codable {
    let relyingPartyIdentifier: String
    let challenge: String?
    let clientData: String?
    let userID: String
    let name: String
    let displayName: String?
    let userVerificationPreference: String?
    let attestationPreference: String?
    let excludedCredentials: [AuthServicesSecurityKeyCredentialDescriptorPayload]?
    let credentialParameters: [Int]?
    let residentKeyPreference: String?
}

private struct AuthServicesSecurityKeyAssertionRequestPayload: Codable {
    let relyingPartyIdentifier: String
    let challenge: String?
    let clientData: String?
    let allowedCredentials: [AuthServicesSecurityKeyCredentialDescriptorPayload]?
    let userVerificationPreference: String?
    let appID: String?
}

@available(macOS 15.0, *)
private func authservicesPlatformRequestStyleName(
    _ requestStyle: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.RequestStyle
) -> String {
    switch requestStyle {
    case .standard:
        return "standard"
    case .conditional:
        return "conditional"
    @unknown default:
        return "standard"
    }
}

@available(macOS 15.0, *)
private func authservicesPlatformRequestStyle(
    _ name: String
) throws -> ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.RequestStyle {
    switch name {
    case "standard":
        return .standard
    case "conditional":
        return .conditional
    default:
        throw AuthServicesBridgeError.invalidArgument("unknown requestStyle: \(name)")
    }
}

@available(macOS 13.5, *)
func authservicesAttachmentRawValue(_ attachment: ASAuthorizationPublicKeyCredentialAttachment) -> Int {
    switch attachment {
    case .platform:
        return 0
    case .crossPlatform:
        return 1
    @unknown default:
        return 0
    }
}

@available(macOS 14.0, *)
private func authservicesMakeLargeBlobRegistrationInput(
    _ payload: AuthServicesLargeBlobRegistrationInputPayload?
) throws -> ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput? {
    guard let payload else { return nil }
    guard #available(macOS 14.0, *) else {
        throw AuthServicesBridgeError.notSupported("largeBlob registration input requires macOS 14.0")
    }
    switch payload.supportRequirement {
    case "preferred":
        return .supportPreferred
    case "required":
        return .supportRequired
    default:
        throw AuthServicesBridgeError.invalidArgument(
            "unknown largeBlob support requirement: \(payload.supportRequirement)"
        )
    }
}

@available(macOS 14.0, *)
private func authservicesLargeBlobRegistrationInputPayload(
    _ input: ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput?
) -> AuthServicesLargeBlobRegistrationInputPayload? {
    guard #available(macOS 14.0, *), let input else { return nil }
    let supportRequirement: String
    switch input.supportRequirement {
    case .preferred:
        supportRequirement = "preferred"
    case .required:
        supportRequirement = "required"
    @unknown default:
        supportRequirement = "preferred"
    }
    return AuthServicesLargeBlobRegistrationInputPayload(supportRequirement: supportRequirement)
}

@available(macOS 14.0, *)
private func authservicesMakeLargeBlobAssertionInput(
    _ payload: AuthServicesLargeBlobAssertionInputPayload?
) throws -> ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput? {
    guard let payload else { return nil }
    guard #available(macOS 14.0, *) else {
        throw AuthServicesBridgeError.notSupported("largeBlob assertion input requires macOS 14.0")
    }
    switch payload.operation {
    case "read":
        return .read
    case "write":
        return .write(try authservicesDecodeBase64(payload.data ?? "", field: "largeBlob.data"))
    default:
        throw AuthServicesBridgeError.invalidArgument(
            "unknown largeBlob assertion operation: \(payload.operation)"
        )
    }
}

@available(macOS 14.0, *)
func authservicesLargeBlobAssertionOutputPayloadIfAvailable(
    _ output: ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput?
) -> (kind: String?, data: String?, success: Bool?) {
    guard #available(macOS 14.0, *), let output else {
        return (nil, nil, nil)
    }
    switch output.result {
    case .read(let data):
        return ("read", data?.base64EncodedString(), nil)
    case .write(let success):
        return ("write", nil, success)
    @unknown default:
        return (nil, nil, nil)
    }
}

@available(macOS 14.0, *)
private func authservicesLargeBlobAssertionInputPayload(
    _ input: ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput?
) -> AuthServicesLargeBlobAssertionInputPayload? {
    guard #available(macOS 14.0, *), let input else { return nil }
    switch input.operation {
    case .read:
        return AuthServicesLargeBlobAssertionInputPayload(operation: "read", data: nil)
    case .write(let data):
        return AuthServicesLargeBlobAssertionInputPayload(
            operation: "write",
            data: data.base64EncodedString()
        )
    @unknown default:
        return nil
    }
}

@available(macOS 15.0, *)
private func authservicesMakePRFInputValues(
    _ payload: AuthServicesPRFInputValuesPayload
) throws -> ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues {
    ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
        saltInput1: try authservicesDecodeBase64(payload.saltInput1, field: "prf.saltInput1"),
        saltInput2: try authservicesDecodeOptionalBase64(payload.saltInput2, field: "prf.saltInput2")
    )
}

@available(macOS 15.0, *)
private func authservicesPRFInputValuesPayload(
    _ inputValues: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
) -> AuthServicesPRFInputValuesPayload {
    AuthServicesPRFInputValuesPayload(
        saltInput1: inputValues.saltInput1.base64EncodedString(),
        saltInput2: inputValues.saltInput2?.base64EncodedString()
    )
}

@available(macOS 15.0, *)
private func authservicesMakePRFRegistrationInput(
    payload: AuthServicesPRFInputValuesPayload?,
    shouldCheckForSupport: Bool?
) throws -> ASAuthorizationPublicKeyCredentialPRFRegistrationInput? {
    guard payload != nil || shouldCheckForSupport == true else { return nil }
    guard #available(macOS 15.0, *) else {
        throw AuthServicesBridgeError.notSupported("PRF registration input requires macOS 15.0")
    }
    if let payload {
        return .inputValues(try authservicesMakePRFInputValues(payload))
    }
    return .checkForSupport
}

@available(macOS 15.0, *)
private func authservicesMakePRFAssertionInput(
    _ payload: AuthServicesPRFAssertionInputPayload?
) throws -> ASAuthorizationPublicKeyCredentialPRFAssertionInput? {
    guard let payload else { return nil }
    guard #available(macOS 15.0, *) else {
        throw AuthServicesBridgeError.notSupported("PRF assertion input requires macOS 15.0")
    }
    let inputValues = try payload.inputValues.map(authservicesMakePRFInputValues)
    let perCredentialInputValues = try payload.perCredentialInputValues?.reduce(
        into: [Data: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues]()
    ) { partialResult, entry in
        partialResult[
            try authservicesDecodeBase64(entry.credentialID, field: "credentialID")
        ] = try authservicesMakePRFInputValues(entry.inputValues)
    }
    if let inputValues {
        return .inputValues(inputValues, perCredentialInputValues: perCredentialInputValues ?? [:])
    }
    if let perCredentialInputValues {
        return .perCredentialInputValues(perCredentialInputValues)
    }
    return nil
}

@available(macOS 15.0, *)
func authservicesPRFOutputPayloadIfAvailable(
    _ output: ASAuthorizationPublicKeyCredentialPRFAssertionOutput?
) -> (first: String?, second: String?) {
    guard #available(macOS 15.0, *), let output else {
        return (nil, nil)
    }
    return (authservicesSymmetricKeyBase64(output.first), authservicesSymmetricKeyBase64(output.second))
}

@available(macOS 15.0, *)
func authservicesPRFOutputPayloadIfAvailable(
    _ output: ASAuthorizationPublicKeyCredentialPRFRegistrationOutput?
) -> (first: String?, second: String?) {
    guard #available(macOS 15.0, *), let output else {
        return (nil, nil)
    }
    return (authservicesSymmetricKeyBase64(output.first), authservicesSymmetricKeyBase64(output.second))
}

private func authservicesPlatformDescriptorPayload(
    _ descriptor: ASAuthorizationPlatformPublicKeyCredentialDescriptor
) -> AuthServicesPlatformCredentialDescriptorPayload {
    AuthServicesPlatformCredentialDescriptorPayload(
        credentialID: descriptor.credentialID.base64EncodedString()
    )
}

private func authservicesCreatePlatformDescriptor(
    _ payload: AuthServicesPlatformCredentialDescriptorPayload
) throws -> ASAuthorizationPlatformPublicKeyCredentialDescriptor {
    ASAuthorizationPlatformPublicKeyCredentialDescriptor(
        credentialID: try authservicesDecodeBase64(payload.credentialID, field: "credentialID")
    )
}

func authservicesSecurityTransportName(
    _ transport: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport
) -> String {
    transport.rawValue
}

private func authservicesCreateSecurityTransport(
    _ name: String
) throws -> ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport {
    switch name {
    case "usb":
        return .usb
    case "nfc":
        return .nfc
    case "bluetooth":
        return .bluetooth
    default:
        throw AuthServicesBridgeError.invalidArgument("unknown security-key transport: \(name)")
    }
}

private func authservicesSecurityDescriptorPayload(
    _ descriptor: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor
) -> AuthServicesSecurityKeyCredentialDescriptorPayload {
    AuthServicesSecurityKeyCredentialDescriptorPayload(
        credentialID: descriptor.credentialID.base64EncodedString(),
        transports: descriptor.transports.map(authservicesSecurityTransportName)
    )
}

private func authservicesCreateSecurityDescriptor(
    _ payload: AuthServicesSecurityKeyCredentialDescriptorPayload
) throws -> ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor {
    let transports: [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport]
    if payload.transports?.contains("allSupported") == true {
        transports = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
    } else {
        transports = try payload.transports?.map(authservicesCreateSecurityTransport) ?? []
    }
    return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
        credentialID: try authservicesDecodeBase64(payload.credentialID, field: "credentialID"),
        transports: transports
    )
}

private func authservicesBuildPlatformRegistrationRequestPayload(
    _ request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest
) -> AuthServicesPlatformRegistrationRequestPayload {
    let clientData: String? = nil
    let requestStyle: String?
    if #available(macOS 15.0, *) {
        requestStyle = authservicesPlatformRequestStyleName(request.requestStyle)
    } else {
        requestStyle = nil
    }
    let prfPayload: AuthServicesPRFInputValuesPayload?
    let prfShouldCheckForSupport: Bool?
    if #available(macOS 15.0, *), let prf = request.prf {
        prfPayload = prf.inputValues.map(authservicesPRFInputValuesPayload)
        prfShouldCheckForSupport = prf.shouldCheckForSupport
    } else {
        prfPayload = nil
        prfShouldCheckForSupport = nil
    }
    return AuthServicesPlatformRegistrationRequestPayload(
        relyingPartyIdentifier: request.relyingPartyIdentifier,
        challenge: request.challenge.base64EncodedString(),
        clientData: clientData,
        userID: request.userID.base64EncodedString(),
        name: request.name,
        displayName: request.displayName,
        requestStyle: requestStyle,
        userVerificationPreference: request.userVerificationPreference.rawValue,
        attestationPreference: request.attestationPreference.rawValue,
        largeBlob: {
            if #available(macOS 14.0, *) {
                return authservicesLargeBlobRegistrationInputPayload(request.largeBlob)
            }
            return nil
        }(),
        prf: prfPayload,
        prfShouldCheckForSupport: prfShouldCheckForSupport
    )
}

private func authservicesApplyPlatformRegistrationRequestPayload(
    _ payload: AuthServicesPlatformRegistrationRequestPayload,
    to request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest
) throws {
    request.displayName = payload.displayName ?? payload.name
    request.userVerificationPreference = .init(rawValue: payload.userVerificationPreference ?? "preferred")
    request.attestationPreference = .init(rawValue: payload.attestationPreference ?? "none")
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    if let requestStyle = payload.requestStyle {
        guard #available(macOS 15.0, *) else {
            throw AuthServicesBridgeError.notSupported("platform passkey requestStyle requires macOS 15.0")
        }
        request.requestStyle = try authservicesPlatformRequestStyle(requestStyle)
    }
    if #available(macOS 14.0, *), let largeBlob = try authservicesMakeLargeBlobRegistrationInput(payload.largeBlob) {
        request.largeBlob = largeBlob
    }
    if #available(macOS 15.0, *), let prf = try authservicesMakePRFRegistrationInput(payload: payload.prf, shouldCheckForSupport: payload.prfShouldCheckForSupport) {
        request.prf = prf
    }
}

private func authservicesCreatePlatformRegistrationRequest(
    _ payload: AuthServicesPlatformRegistrationRequestPayload
) throws -> ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: payload.relyingPartyIdentifier
    )
    let request: ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    request = provider.createCredentialRegistrationRequest(
        challenge: try authservicesDecodeBase64(payload.challenge ?? "", field: "challenge"),
        name: payload.name,
        userID: try authservicesDecodeBase64(payload.userID, field: "userID")
    )
    try authservicesApplyPlatformRegistrationRequestPayload(payload, to: request)
    return request
}

private func authservicesBuildPlatformAssertionRequestPayload(
    _ request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
) -> AuthServicesPlatformAssertionRequestPayload {
    let clientData: String? = nil
    let prfPayload: AuthServicesPRFAssertionInputPayload?
    if #available(macOS 15.0, *), let prf = request.prf {
        let perCredentialInputValues = prf.perCredentialInputValues?.map { entry in
            AuthServicesPRFAssertionPerCredentialInputPayload(
                credentialID: entry.key.base64EncodedString(),
                inputValues: authservicesPRFInputValuesPayload(entry.value)
            )
        }
        prfPayload = AuthServicesPRFAssertionInputPayload(
            inputValues: prf.inputValues.map(authservicesPRFInputValuesPayload),
            perCredentialInputValues: perCredentialInputValues
        )
    } else {
        prfPayload = nil
    }
    return AuthServicesPlatformAssertionRequestPayload(
        relyingPartyIdentifier: request.relyingPartyIdentifier,
        challenge: request.challenge.base64EncodedString(),
        clientData: clientData,
        allowedCredentials: request.allowedCredentials.map(authservicesPlatformDescriptorPayload),
        userVerificationPreference: request.userVerificationPreference.rawValue,
        largeBlob: {
            if #available(macOS 14.0, *) {
                return authservicesLargeBlobAssertionInputPayload(request.largeBlob)
            }
            return nil
        }(),
        prf: prfPayload
    )
}

private func authservicesApplyPlatformAssertionRequestPayload(
    _ payload: AuthServicesPlatformAssertionRequestPayload,
    to request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
) throws {
    if let allowedCredentials = payload.allowedCredentials {
        request.allowedCredentials = try allowedCredentials.map(authservicesCreatePlatformDescriptor)
    }
    request.userVerificationPreference = .init(rawValue: payload.userVerificationPreference ?? "preferred")
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    if #available(macOS 14.0, *), let largeBlob = try authservicesMakeLargeBlobAssertionInput(payload.largeBlob) {
        request.largeBlob = largeBlob
    }
    if #available(macOS 15.0, *), let prf = try authservicesMakePRFAssertionInput(payload.prf) {
        request.prf = prf
    }
}

private func authservicesCreatePlatformAssertionRequest(
    _ payload: AuthServicesPlatformAssertionRequestPayload
) throws -> ASAuthorizationPlatformPublicKeyCredentialAssertionRequest {
    let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
        relyingPartyIdentifier: payload.relyingPartyIdentifier
    )
    let request: ASAuthorizationPlatformPublicKeyCredentialAssertionRequest
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    request = provider.createCredentialAssertionRequest(
        challenge: try authservicesDecodeBase64(payload.challenge ?? "", field: "challenge")
    )
    try authservicesApplyPlatformAssertionRequestPayload(payload, to: request)
    return request
}

private func authservicesBuildSecurityKeyRegistrationRequestPayload(
    _ request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest
) -> AuthServicesSecurityKeyRegistrationRequestPayload {
    let clientData: String? = nil
    return AuthServicesSecurityKeyRegistrationRequestPayload(
        relyingPartyIdentifier: request.relyingPartyIdentifier,
        challenge: request.challenge.base64EncodedString(),
        clientData: clientData,
        userID: request.userID.base64EncodedString(),
        name: request.name,
        displayName: request.displayName,
        userVerificationPreference: request.userVerificationPreference.rawValue,
        attestationPreference: request.attestationPreference.rawValue,
        excludedCredentials: request.excludedCredentials.map(authservicesSecurityDescriptorPayload),
        credentialParameters: request.credentialParameters.map { Int($0.algorithm.rawValue) },
        residentKeyPreference: request.residentKeyPreference.rawValue
    )
}

private func authservicesApplySecurityKeyRegistrationRequestPayload(
    _ payload: AuthServicesSecurityKeyRegistrationRequestPayload,
    to request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest
) throws {
    request.userVerificationPreference = .init(rawValue: payload.userVerificationPreference ?? "preferred")
    request.attestationPreference = .init(rawValue: payload.attestationPreference ?? "none")
    request.residentKeyPreference = .init(rawValue: payload.residentKeyPreference ?? "discouraged")
    if let excludedCredentials = payload.excludedCredentials {
        request.excludedCredentials = try excludedCredentials.map(authservicesCreateSecurityDescriptor)
    }
    if let credentialParameters = payload.credentialParameters {
        request.credentialParameters = credentialParameters.map {
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .init(rawValue: $0))
        }
    }
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
}

private func authservicesCreateSecurityKeyRegistrationRequest(
    _ payload: AuthServicesSecurityKeyRegistrationRequestPayload
) throws -> ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest {
    let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
        relyingPartyIdentifier: payload.relyingPartyIdentifier
    )
    let displayName = payload.displayName ?? payload.name
    let request: ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    request = provider.createCredentialRegistrationRequest(
        challenge: try authservicesDecodeBase64(payload.challenge ?? "", field: "challenge"),
        displayName: displayName,
        name: payload.name,
        userID: try authservicesDecodeBase64(payload.userID, field: "userID")
    )
    try authservicesApplySecurityKeyRegistrationRequestPayload(payload, to: request)
    return request
}

private func authservicesBuildSecurityKeyAssertionRequestPayload(
    _ request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest
) -> AuthServicesSecurityKeyAssertionRequestPayload {
    let clientData: String? = nil
    return AuthServicesSecurityKeyAssertionRequestPayload(
        relyingPartyIdentifier: request.relyingPartyIdentifier,
        challenge: request.challenge.base64EncodedString(),
        clientData: clientData,
        allowedCredentials: request.allowedCredentials.map(authservicesSecurityDescriptorPayload),
        userVerificationPreference: request.userVerificationPreference.rawValue,
        appID: {
            if #available(macOS 14.5, *) {
                return request.appID
            }
            return nil
        }()
    )
}

private func authservicesApplySecurityKeyAssertionRequestPayload(
    _ payload: AuthServicesSecurityKeyAssertionRequestPayload,
    to request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest
) throws {
    if let allowedCredentials = payload.allowedCredentials {
        request.allowedCredentials = try allowedCredentials.map(authservicesCreateSecurityDescriptor)
    }
    request.userVerificationPreference = .init(rawValue: payload.userVerificationPreference ?? "preferred")
    if let appID = payload.appID {
        guard #available(macOS 14.5, *) else {
            throw AuthServicesBridgeError.notSupported("security-key appID requires macOS 14.5")
        }
        request.appID = appID
    }
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
}

private func authservicesCreateSecurityKeyAssertionRequest(
    _ payload: AuthServicesSecurityKeyAssertionRequestPayload
) throws -> ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest {
    let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
        relyingPartyIdentifier: payload.relyingPartyIdentifier
    )
    let request: ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest
    if payload.clientData != nil {
        throw authservicesUnsupportedClientData()
    }
    request = provider.createCredentialAssertionRequest(
        challenge: try authservicesDecodeBase64(payload.challenge ?? "", field: "challenge")
    )
    try authservicesApplySecurityKeyAssertionRequestPayload(payload, to: request)
    return request
}

@_cdecl("authservices_passkey_registration_request_create")
public func authservices_passkey_registration_request_create(
    _ relyingPartyID: UnsafePointer<CChar>?,
    _ challengeBase64: UnsafePointer<CChar>?,
    _ userIDBase64: UnsafePointer<CChar>?,
    _ userName: UnsafePointer<CChar>?,
    _ userDisplayName: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard
        let relyingPartyID = relyingPartyID.map({ String(cString: $0) }),
        let challengeBase64 = challengeBase64.map({ String(cString: $0) }),
        let userIDBase64 = userIDBase64.map({ String(cString: $0) }),
        let userName = userName.map({ String(cString: $0) })
    else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument(
                "relying_party_id, challenge_b64, user_id_b64, and user_name are required"
            )
        )
        return nil
    }
    do {
        let payload = AuthServicesPlatformRegistrationRequestPayload(
            relyingPartyIdentifier: relyingPartyID,
            challenge: challengeBase64,
            clientData: nil,
            userID: userIDBase64,
            name: userName,
            displayName: userDisplayName.map { String(cString: $0) },
            requestStyle: nil,
            userVerificationPreference: nil,
            attestationPreference: nil,
            largeBlob: nil,
            prf: nil,
            prfShouldCheckForSupport: nil
        )
        return authservices_retain(ASPasskeyRegistrationRequestHandle(try authservicesCreatePlatformRegistrationRequest(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
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
    let payload = authservicesBuildPlatformRegistrationRequestPayload(
        authservices_borrow(ptr, as: ASPasskeyRegistrationRequestHandle.self).request
    )
    return authservicesCopyJSON(
        AuthServicesRequestKindPayload(
            kind: "passkey_registration",
            relyingPartyIdentifier: payload.relyingPartyIdentifier,
            challenge: payload.challenge,
            userID: payload.userID,
            userName: payload.name,
            userDisplayName: payload.displayName
        )
    )
}

@_cdecl("authservices_passkey_registration_request_copy_json")
public func authservices_passkey_registration_request_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesBuildPlatformRegistrationRequestPayload(
            authservices_borrow(ptr, as: ASPasskeyRegistrationRequestHandle.self).request
        )
    )
}

@_cdecl("authservices_passkey_registration_request_update_from_json")
public func authservices_passkey_registration_request_update_from_json(
    _ ptr: UnsafeMutableRawPointer?,
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null platform passkey registration request handle")
        )
    }
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesPlatformRegistrationRequestPayload.self
        )
        let handle = authservices_borrow(ptr, as: ASPasskeyRegistrationRequestHandle.self)
        try authservicesApplyPlatformRegistrationRequestPayload(payload, to: handle.request)
        return AUTHSERVICES_OK
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_passkey_assertion_request_create")
public func authservices_passkey_assertion_request_create(
    _ relyingPartyID: UnsafePointer<CChar>?,
    _ challengeBase64: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard
        let relyingPartyID = relyingPartyID.map({ String(cString: $0) }),
        let challengeBase64 = challengeBase64.map({ String(cString: $0) })
    else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument(
                "relying_party_id and challenge_b64 are required"
            )
        )
        return nil
    }
    do {
        let payload = AuthServicesPlatformAssertionRequestPayload(
            relyingPartyIdentifier: relyingPartyID,
            challenge: challengeBase64,
            clientData: nil,
            allowedCredentials: nil,
            userVerificationPreference: nil,
            largeBlob: nil,
            prf: nil
        )
        return authservices_retain(ASPasskeyAssertionRequestHandle(try authservicesCreatePlatformAssertionRequest(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
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
    let payload = authservicesBuildPlatformAssertionRequestPayload(
        authservices_borrow(ptr, as: ASPasskeyAssertionRequestHandle.self).request
    )
    return authservicesCopyJSON(
        AuthServicesRequestKindPayload(
            kind: "passkey_assertion",
            relyingPartyIdentifier: payload.relyingPartyIdentifier,
            challenge: payload.challenge,
            userID: nil,
            userName: nil,
            userDisplayName: nil
        )
    )
}

@_cdecl("authservices_passkey_assertion_request_copy_json")
public func authservices_passkey_assertion_request_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesBuildPlatformAssertionRequestPayload(
            authservices_borrow(ptr, as: ASPasskeyAssertionRequestHandle.self).request
        )
    )
}

@_cdecl("authservices_passkey_assertion_request_update_from_json")
public func authservices_passkey_assertion_request_update_from_json(
    _ ptr: UnsafeMutableRawPointer?,
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null platform passkey assertion request handle")
        )
    }
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesPlatformAssertionRequestPayload.self
        )
        let handle = authservices_borrow(ptr, as: ASPasskeyAssertionRequestHandle.self)
        try authservicesApplyPlatformAssertionRequestPayload(payload, to: handle.request)
        return AUTHSERVICES_OK
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_security_key_registration_request_create_from_json")
public func authservices_security_key_registration_request_create_from_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesSecurityKeyRegistrationRequestPayload.self
        )
        return authservices_retain(ASSecurityKeyRegistrationRequestHandle(try authservicesCreateSecurityKeyRegistrationRequest(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_security_key_registration_request_copy_json")
public func authservices_security_key_registration_request_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesBuildSecurityKeyRegistrationRequestPayload(
            authservices_borrow(ptr, as: ASSecurityKeyRegistrationRequestHandle.self).request
        )
    )
}

@_cdecl("authservices_security_key_registration_request_update_from_json")
public func authservices_security_key_registration_request_update_from_json(
    _ ptr: UnsafeMutableRawPointer?,
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null security-key registration request handle")
        )
    }
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesSecurityKeyRegistrationRequestPayload.self
        )
        let handle = authservices_borrow(ptr, as: ASSecurityKeyRegistrationRequestHandle.self)
        try authservicesApplySecurityKeyRegistrationRequestPayload(payload, to: handle.request)
        return AUTHSERVICES_OK
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_security_key_registration_request_release")
public func authservices_security_key_registration_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_security_key_assertion_request_create_from_json")
public func authservices_security_key_assertion_request_create_from_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesSecurityKeyAssertionRequestPayload.self
        )
        return authservices_retain(ASSecurityKeyAssertionRequestHandle(try authservicesCreateSecurityKeyAssertionRequest(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_security_key_assertion_request_copy_json")
public func authservices_security_key_assertion_request_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesBuildSecurityKeyAssertionRequestPayload(
            authservices_borrow(ptr, as: ASSecurityKeyAssertionRequestHandle.self).request
        )
    )
}

@_cdecl("authservices_security_key_assertion_request_update_from_json")
public func authservices_security_key_assertion_request_update_from_json(
    _ ptr: UnsafeMutableRawPointer?,
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null security-key assertion request handle")
        )
    }
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesSecurityKeyAssertionRequestPayload.self
        )
        let handle = authservices_borrow(ptr, as: ASSecurityKeyAssertionRequestHandle.self)
        try authservicesApplySecurityKeyAssertionRequestPayload(payload, to: handle.request)
        return AUTHSERVICES_OK
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_security_key_assertion_request_release")
public func authservices_security_key_assertion_request_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_platform_credential_descriptor_create_from_json")
public func authservices_platform_credential_descriptor_create_from_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesPlatformCredentialDescriptorPayload.self
        )
        return authservices_retain(ASPlatformCredentialDescriptorHandle(try authservicesCreatePlatformDescriptor(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_platform_credential_descriptor_copy_json")
public func authservices_platform_credential_descriptor_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesPlatformDescriptorPayload(
            authservices_borrow(ptr, as: ASPlatformCredentialDescriptorHandle.self).descriptor
        )
    )
}

@_cdecl("authservices_platform_credential_descriptor_release")
public func authservices_platform_credential_descriptor_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_security_key_credential_descriptor_create_from_json")
public func authservices_security_key_credential_descriptor_create_from_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesSecurityKeyCredentialDescriptorPayload.self
        )
        return authservices_retain(ASSecurityKeyCredentialDescriptorHandle(try authservicesCreateSecurityDescriptor(payload)))
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_security_key_credential_descriptor_copy_json")
public func authservices_security_key_credential_descriptor_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    return authservicesCopyJSON(
        authservicesSecurityDescriptorPayload(
            authservices_borrow(ptr, as: ASSecurityKeyCredentialDescriptorHandle.self).descriptor
        )
    )
}

@_cdecl("authservices_security_key_credential_descriptor_release")
public func authservices_security_key_credential_descriptor_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}
