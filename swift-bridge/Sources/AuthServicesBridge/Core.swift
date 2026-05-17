import Foundation
import AuthenticationServices

let AUTHSERVICES_OK: Int32 = 0
let AUTHSERVICES_INVALID_ARGUMENT: Int32 = -1
let AUTHSERVICES_TIMED_OUT: Int32 = -2
let AUTHSERVICES_NOT_SUPPORTED: Int32 = -3
let AUTHSERVICES_FRAMEWORK_ERROR: Int32 = -4
let AUTHSERVICES_CANCELLED: Int32 = -5
let AUTHSERVICES_UNKNOWN: Int32 = -99

@inline(__always)
func authservices_retain<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(object).toOpaque()
}

@inline(__always)
func authservices_borrow<T: AnyObject>(_ ptr: UnsafeMutableRawPointer, as _: T.Type = T.self) -> T {
    Unmanaged<T>.fromOpaque(ptr).takeUnretainedValue()
}

@inline(__always)
func authservices_release(_ ptr: UnsafeMutableRawPointer) {
    Unmanaged<AnyObject>.fromOpaque(ptr).release()
}

@inline(__always)
func authservicesCString(_ string: String) -> UnsafeMutablePointer<CChar>? {
    string.withCString { strdup($0) }
}

@inline(__always)
func authservicesCopyJSON<T: Encodable>(_ value: T) -> UnsafeMutablePointer<CChar>? {
    (try? authservicesEncodeJSON(value)).flatMap(authservicesCString)
}

func authservicesEncodeJSON<T: Encodable>(_ value: T) throws -> String {
    let data = try JSONEncoder().encode(value)
    guard let string = String(data: data, encoding: .utf8) else {
        throw AuthServicesBridgeError.unknown("failed to encode JSON as UTF-8")
    }
    return string
}

func authservicesDecodeJSON<T: Decodable>(_ cString: UnsafePointer<CChar>?, as type: T.Type) throws -> T {
    guard let cString else {
        throw AuthServicesBridgeError.invalidArgument("missing JSON payload")
    }
    let data = Data(String(cString: cString).utf8)
    do {
        return try JSONDecoder().decode(T.self, from: data)
    } catch {
        throw AuthServicesBridgeError.invalidArgument("invalid JSON payload: \(error.localizedDescription)")
    }
}

func authservicesDecodeBase64(_ value: String, field: String) throws -> Data {
    guard let data = Data(base64Encoded: value, options: .ignoreUnknownCharacters) else {
        throw AuthServicesBridgeError.invalidArgument("invalid base64 payload for \(field)")
    }
    return data
}

func authservicesDecodeOptionalBase64(_ value: String?, field: String) throws -> Data? {
    guard let value else { return nil }
    return try authservicesDecodeBase64(value, field: field)
}

@discardableResult
func authservicesFail(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    with error: Error
) -> Int32 {
    authservicesPopulateError(outError, with: error)
    return authservicesStatus(for: error)
}

func authservicesBlockOnAsync<T>(
    timeoutSeconds: Int = 30,
    work: @escaping () async throws -> T,
    onSuccess: @escaping (T) -> Void,
    onError: @escaping (Error) -> Void
) -> Int32 {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<T, Error>?
    Task {
        do {
            result = .success(try await work())
        } catch {
            result = .failure(error)
        }
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .success else {
        onError(AuthServicesBridgeError.timedOut("AuthenticationServices operation timed out"))
        return AUTHSERVICES_TIMED_OUT
    }
    switch result {
    case .success(let value):
        onSuccess(value)
        return AUTHSERVICES_OK
    case .failure(let error):
        onError(error)
        return authservicesStatus(for: error)
    case .none:
        let error = AuthServicesBridgeError.unknown("AuthenticationServices operation produced no result")
        onError(error)
        return error.statusCode
    }
}

enum AuthServicesBridgeError: Error {
    case invalidArgument(String)
    case timedOut(String)
    case notSupported(String)
    case cancelled(String)
    case unknown(String)

    var statusCode: Int32 {
        switch self {
        case .invalidArgument:
            return AUTHSERVICES_INVALID_ARGUMENT
        case .timedOut:
            return AUTHSERVICES_TIMED_OUT
        case .notSupported:
            return AUTHSERVICES_NOT_SUPPORTED
        case .cancelled:
            return AUTHSERVICES_CANCELLED
        case .unknown:
            return AUTHSERVICES_UNKNOWN
        }
    }

    var message: String {
        switch self {
        case .invalidArgument(let message),
             .timedOut(let message),
             .notSupported(let message),
             .cancelled(let message),
             .unknown(let message):
            return message
        }
    }
}

func authservicesStatus(for error: Error) -> Int32 {
    if let error = error as? AuthServicesBridgeError {
        return error.statusCode
    }
    if let error = error as? ASAuthorizationError {
        if error.code == .canceled {
            return AUTHSERVICES_CANCELLED
        }
        return AUTHSERVICES_FRAMEWORK_ERROR
    }
    return AUTHSERVICES_FRAMEWORK_ERROR
}

func authservicesPopulateError(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    with error: Error
) {
    let message: String
    if let error = error as? AuthServicesBridgeError {
        message = error.message
    } else {
        let nsError = error as NSError
        message = "\(nsError.domain):\(nsError.code):\(nsError.localizedDescription)"
    }
    outError?.pointee = authservicesCString(message)
}

@_cdecl("authservices_string_free")
public func authservices_string_free(_ ptr: UnsafeMutablePointer<CChar>?) {
    free(ptr)
}

struct AuthServicesRequestKindPayload: Codable {
    let kind: String
    let relyingPartyIdentifier: String?
    let challenge: String?
    let userID: String?
    let userName: String?
    let userDisplayName: String?
}

struct AuthServicesAuthorizationPayload: Codable {
    let provider: String
    let userIdentifier: String?
    let email: String?
    let fullName: String?
    let identityToken: String?
    let authorizationCode: String?
    let realUserStatus: String?
    let userAgeRange: String?
    let password: String?
    let credentialID: String?
    let rawAttestationObject: String?
    let rawAuthenticatorData: String?
    let signature: String?
    let userID: String?
    let attachment: Int?
    let usedAppID: Bool?
    let transports: [String]?
    let largeBlobResultKind: String?
    let largeBlobData: String?
    let largeBlobWriteSucceeded: Bool?
    let largeBlobSupported: Bool?
    let prfFirst: String?
    let prfSecond: String?
    let prfSupported: Bool?
    let error: String?
}
