import Foundation
import AuthenticationServices

private struct AuthServicesCredentialIdentityStoreStatePayload: Codable {
    let isEnabled: Bool
    let supportsIncrementalUpdates: Bool
}

private struct AuthServicesCredentialServiceIdentifierPayload: Codable {
    let identifier: String
    let type: String
    let displayName: String?
}

private struct AuthServicesCredentialIdentityPayload: Codable {
    let kind: String
    let serviceIdentifier: AuthServicesCredentialServiceIdentifierPayload?
    let relyingPartyIdentifier: String?
    let user: String?
    let userName: String?
    let credentialID: String?
    let userHandle: String?
    let label: String?
    let recordIdentifier: String?
    let rank: Int?
}

private func authservicesRequired<T>(_ value: T?, _ field: String, kind: String) throws -> T {
    guard let value else {
        throw AuthServicesBridgeError.invalidArgument("\(kind) credential identities require \(field)")
    }
    return value
}

private func authservicesServiceIdentifier(
    from payload: AuthServicesCredentialServiceIdentifierPayload
) throws -> ASCredentialServiceIdentifier {
    let type: ASCredentialServiceIdentifier.IdentifierType
    switch payload.type {
    case "domain":
        type = .domain
    case "url":
        type = .URL
    case "app":
        guard #available(macOS 26.2, *) else {
            throw AuthServicesBridgeError.notSupported("app service identifiers require macOS 26.2")
        }
        type = .app
    default:
        throw AuthServicesBridgeError.invalidArgument("unknown service identifier type: \(payload.type)")
    }
    if let displayName = payload.displayName {
        guard #available(macOS 26.2, *) else {
            throw AuthServicesBridgeError.notSupported("service identifier display names require macOS 26.2")
        }
        return ASCredentialServiceIdentifier(identifier: payload.identifier, type: type, displayName: displayName)
    }
    return ASCredentialServiceIdentifier(identifier: payload.identifier, type: type)
}

private func authservicesServiceIdentifierPayload(
    _ serviceIdentifier: ASCredentialServiceIdentifier
) -> AuthServicesCredentialServiceIdentifierPayload {
    var type = serviceIdentifier.type == .URL ? "url" : "domain"
    var displayName: String?
    if #available(macOS 26.2, *) {
        if serviceIdentifier.type == .app {
            type = "app"
        }
        displayName = serviceIdentifier.displayName
    }
    return AuthServicesCredentialServiceIdentifierPayload(
        identifier: serviceIdentifier.identifier,
        type: type,
        displayName: displayName
    )
}

private func authservicesPasswordIdentity(
    from payload: AuthServicesCredentialIdentityPayload
) throws -> ASPasswordCredentialIdentity {
    let identity = ASPasswordCredentialIdentity(
        serviceIdentifier: try authservicesServiceIdentifier(
            from: try authservicesRequired(payload.serviceIdentifier, "a service identifier", kind: "password")
        ),
        user: try authservicesRequired(payload.user, "a user", kind: "password"),
        recordIdentifier: payload.recordIdentifier
    )
    identity.rank = payload.rank ?? 0
    return identity
}

@available(macOS 14.0, *)
private func authservicesCredentialIdentity(
    from payload: AuthServicesCredentialIdentityPayload
) throws -> ASCredentialIdentity {
    switch payload.kind {
    case "password":
        return try authservicesPasswordIdentity(from: payload)
    case "passkey":
        let identity = ASPasskeyCredentialIdentity(
            relyingPartyIdentifier: try authservicesRequired(
                payload.relyingPartyIdentifier,
                "a relying party identifier",
                kind: "passkey"
            ),
            userName: try authservicesRequired(payload.userName, "a user name", kind: "passkey"),
            credentialID: try authservicesDecodeBase64(
                try authservicesRequired(payload.credentialID, "a credential ID", kind: "passkey"),
                field: "credentialID"
            ),
            userHandle: try authservicesDecodeBase64(
                try authservicesRequired(payload.userHandle, "a user handle", kind: "passkey"),
                field: "userHandle"
            ),
            recordIdentifier: payload.recordIdentifier
        )
        identity.rank = payload.rank ?? 0
        return identity
    case "one_time_code":
        guard #available(macOS 15.0, *) else {
            throw AuthServicesBridgeError.notSupported("one-time-code credential identities require macOS 15.0")
        }
        let identity = ASOneTimeCodeCredentialIdentity(
            serviceIdentifier: try authservicesServiceIdentifier(
                from: try authservicesRequired(payload.serviceIdentifier, "a service identifier", kind: "one-time-code")
            ),
            label: try authservicesRequired(payload.label, "a label", kind: "one-time-code"),
            recordIdentifier: payload.recordIdentifier
        )
        identity.rank = payload.rank ?? 0
        return identity
    default:
        throw AuthServicesBridgeError.invalidArgument("unknown credential identity kind: \(payload.kind)")
    }
}

@available(macOS 14.0, *)
private func authservicesCredentialIdentityPayload(
    _ identity: ASCredentialIdentity
) -> AuthServicesCredentialIdentityPayload? {
    if let identity = identity as? ASPasswordCredentialIdentity {
        return AuthServicesCredentialIdentityPayload(
            kind: "password",
            serviceIdentifier: authservicesServiceIdentifierPayload(identity.serviceIdentifier),
            relyingPartyIdentifier: nil,
            user: identity.user,
            userName: nil,
            credentialID: nil,
            userHandle: nil,
            label: nil,
            recordIdentifier: identity.recordIdentifier,
            rank: identity.rank
        )
    }
    if let identity = identity as? ASPasskeyCredentialIdentity {
        return AuthServicesCredentialIdentityPayload(
            kind: "passkey",
            serviceIdentifier: nil,
            relyingPartyIdentifier: identity.relyingPartyIdentifier,
            user: nil,
            userName: identity.userName,
            credentialID: identity.credentialID.base64EncodedString(),
            userHandle: identity.userHandle.base64EncodedString(),
            label: nil,
            recordIdentifier: identity.recordIdentifier,
            rank: identity.rank
        )
    }
    if #available(macOS 15.0, *), let identity = identity as? ASOneTimeCodeCredentialIdentity {
        return AuthServicesCredentialIdentityPayload(
            kind: "one_time_code",
            serviceIdentifier: authservicesServiceIdentifierPayload(identity.serviceIdentifier),
            relyingPartyIdentifier: nil,
            user: nil,
            userName: nil,
            credentialID: nil,
            userHandle: nil,
            label: identity.label,
            recordIdentifier: identity.recordIdentifier,
            rank: identity.rank
        )
    }
    return nil
}

private enum AuthServicesCredentialIdentityBatch {
    case passwords([ASPasswordCredentialIdentity])
    case identities([Any])
}

private func authservicesCredentialIdentityBatch(
    _ payloadJson: UnsafePointer<CChar>?
) throws -> AuthServicesCredentialIdentityBatch {
    let payloads = try authservicesDecodeJSON(payloadJson, as: [AuthServicesCredentialIdentityPayload].self)
    if #available(macOS 14.0, *) {
        return .identities(try payloads.map(authservicesCredentialIdentity(from:)))
    }
    guard payloads.allSatisfy({ $0.kind == "password" }) else {
        throw AuthServicesBridgeError.notSupported(
            "passkey and one-time-code credential identities require macOS 14.0"
        )
    }
    return .passwords(try payloads.map(authservicesPasswordIdentity(from:)))
}

private func authservicesCredentialIdentityStoreCall(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ work: @escaping () async throws -> Void
) -> Int32 {
    authservicesBlockOnAsync(
        work: work,
        onSuccess: { _ in },
        onError: { error in
            authservicesPopulateError(outError, with: error)
        }
    )
}

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
            await ASCredentialIdentityStore.shared.state()
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

@_cdecl("authservices_credential_identity_store_save_identities_json")
public func authservices_credential_identity_store_save_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        switch try authservicesCredentialIdentityBatch(payloadJson) {
        case .passwords(let identities):
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.saveCredentialIdentities(identities)
            }
        case .identities(let identities):
            guard #available(macOS 14.0, *), let identities = identities as? [ASCredentialIdentity] else {
                throw AuthServicesBridgeError.unknown("unexpected credential identity batch")
            }
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.saveCredentialIdentities(identities)
            }
        }
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_credential_identity_store_remove_identities_json")
public func authservices_credential_identity_store_remove_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        switch try authservicesCredentialIdentityBatch(payloadJson) {
        case .passwords(let identities):
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.removeCredentialIdentities(identities)
            }
        case .identities(let identities):
            guard #available(macOS 14.0, *), let identities = identities as? [ASCredentialIdentity] else {
                throw AuthServicesBridgeError.unknown("unexpected credential identity batch")
            }
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.removeCredentialIdentities(identities)
            }
        }
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_credential_identity_store_replace_identities_json")
public func authservices_credential_identity_store_replace_identities_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        switch try authservicesCredentialIdentityBatch(payloadJson) {
        case .passwords(let identities):
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(with: identities)
            }
        case .identities(let identities):
            guard #available(macOS 14.0, *), let identities = identities as? [ASCredentialIdentity] else {
                throw AuthServicesBridgeError.unknown("unexpected credential identity batch")
            }
            return authservicesCredentialIdentityStoreCall(outError) {
                try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities)
            }
        }
    } catch {
        return authservicesFail(outError, with: error)
    }
}

@_cdecl("authservices_credential_identity_store_remove_all")
public func authservices_credential_identity_store_remove_all(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    authservicesCredentialIdentityStoreCall(outError) {
        try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}

@_cdecl("authservices_credential_identity_store_identities_json")
public func authservices_credential_identity_store_identities_json(
    _ servicePayloadJson: UnsafePointer<CChar>?,
    _ identityTypesRawValue: UInt64,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutablePointer<CChar>? {
    guard #available(macOS 14.4, *) else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.notSupported("listing credential identities requires macOS 14.4")
        )
        return nil
    }
    let serviceIdentifier: ASCredentialServiceIdentifier?
    let identityTypes: ASCredentialIdentityStore.IdentityTypes
    do {
        serviceIdentifier = try servicePayloadJson.map {
            try authservicesServiceIdentifier(
                from: try authservicesDecodeJSON($0, as: AuthServicesCredentialServiceIdentifierPayload.self)
            )
        }
        guard let rawValue = UInt(exactly: identityTypesRawValue) else {
            throw AuthServicesBridgeError.invalidArgument("credential identity types out of range")
        }
        identityTypes = ASCredentialIdentityStore.IdentityTypes(rawValue: rawValue)
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
    var payloadJson: UnsafeMutablePointer<CChar>?
    let status = authservicesBlockOnAsync(
        work: {
            await ASCredentialIdentityStore.shared.credentialIdentities(
                forService: serviceIdentifier,
                credentialIdentityTypes: identityTypes
            )
        },
        onSuccess: { identities in
            payloadJson = authservicesCopyJSON(identities.compactMap(authservicesCredentialIdentityPayload))
        },
        onError: { error in
            authservicesPopulateError(outError, with: error)
        }
    )
    return status == AUTHSERVICES_OK ? payloadJson : nil
}
