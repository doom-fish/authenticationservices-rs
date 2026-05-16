import Foundation
import AuthenticationServices

// MARK: – Status codes (authservices-prefixed)

let AUTHSERVICES_OK: Int32 = 0
let AUTHSERVICES_INVALID_ARGUMENT: Int32 = -1
let AUTHSERVICES_TIMED_OUT: Int32 = -2
let AUTHSERVICES_NOT_SUPPORTED: Int32 = -3
let AUTHSERVICES_FRAMEWORK_ERROR: Int32 = -4
let AUTHSERVICES_CANCELLED: Int32 = -5
let AUTHSERVICES_UNKNOWN: Int32 = -99

// MARK: – Raw-pointer helpers (authservices-prefixed)

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

// MARK: – C-string helpers

@inline(__always)
func authservicesCString(_ string: String) -> UnsafeMutablePointer<CChar>? {
    string.withCString { strdup($0) }
}

// MARK: – JSON helpers

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

// MARK: – Semaphore / Task helpers

func authservicesBlockOnAsync<T>(
    timeoutSeconds: Int = 30,
    work: @escaping () async throws -> T,
    onSuccess: @escaping (T) -> Void,
    onError: @escaping (Error) -> Void
) -> Int32 {
    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<T, Error>?
    Task {
        do { result = .success(try await work()) }
        catch { result = .failure(error) }
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .success else {
        onError(AuthServicesBridgeError.timedOut("AuthenticationServices operation timed out"))
        return AUTHSERVICES_TIMED_OUT
    }
    switch result {
    case .success(let v): onSuccess(v); return AUTHSERVICES_OK
    case .failure(let e): onError(e); return authservicesStatus(for: e)
    case .none:
        let e = AuthServicesBridgeError.unknown("no result")
        onError(e); return e.statusCode
    }
}

// MARK: – Error handling

enum AuthServicesBridgeError: Error {
    case invalidArgument(String)
    case timedOut(String)
    case notSupported(String)
    case cancelled(String)
    case unknown(String)

    var statusCode: Int32 {
        switch self {
        case .invalidArgument: return AUTHSERVICES_INVALID_ARGUMENT
        case .timedOut:        return AUTHSERVICES_TIMED_OUT
        case .notSupported:    return AUTHSERVICES_NOT_SUPPORTED
        case .cancelled:       return AUTHSERVICES_CANCELLED
        case .unknown:         return AUTHSERVICES_UNKNOWN
        }
    }

    var message: String {
        switch self {
        case .invalidArgument(let m), .timedOut(let m),
             .notSupported(let m), .cancelled(let m), .unknown(let m): return m
        }
    }
}

func authservicesStatus(for error: Error) -> Int32 {
    if let e = error as? AuthServicesBridgeError { return e.statusCode }
    if let e = error as? ASAuthorizationError {
        if e.code == .canceled { return AUTHSERVICES_CANCELLED }
        return AUTHSERVICES_FRAMEWORK_ERROR
    }
    return AUTHSERVICES_FRAMEWORK_ERROR
}

func authservicesPopulateError(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    with error: Error
) {
    let msg: String
    if let e = error as? AuthServicesBridgeError {
        msg = e.message
    } else {
        let ns = error as NSError
        msg = "\(ns.domain):\(ns.code):\(ns.localizedDescription)"
    }
    outError?.pointee = authservicesCString(msg)
}

// MARK: – Shared free

@_cdecl("authservices_string_free")
public func authservices_string_free(_ ptr: UnsafeMutablePointer<CChar>?) {
    free(ptr)
}

// MARK: – JSON payload types

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
    let credentialID: String?
    let rawAttestationObject: String?
    let rawAuthenticatorData: String?
    let signature: String?
    let error: String?
}
