import AppKit
import Foundation
import AuthenticationServices

struct AuthServicesWebAuthenticationCallbackPayload: Codable {
    let kind: String
    let scheme: String?
    let host: String?
    let path: String?
}

struct AuthServicesWebAuthenticationSessionPayload: Codable {
    let url: String
    let callback: AuthServicesWebAuthenticationCallbackPayload?
    let prefersEphemeralWebBrowserSession: Bool
    let additionalHeaderFields: [String: String]?
    let canStart: Bool
    let usesPresentationContextProvider: Bool
}

final class WebAuthSessionPresentationContextProvider: NSObject,
    ASWebAuthenticationPresentationContextProviding {

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        if let window = NSApplication.shared.windows.first {
            return window
        }
        return NSWindow()
    }
}

final class WebAuthSessionHandle {
    let session: ASWebAuthenticationSession
    let url: String
    let callback: AuthServicesWebAuthenticationCallbackPayload?
    let presentationContextProvider: WebAuthSessionPresentationContextProvider

    init(
        session: ASWebAuthenticationSession,
        url: String,
        callback: AuthServicesWebAuthenticationCallbackPayload?,
        presentationContextProvider: WebAuthSessionPresentationContextProvider
    ) {
        self.session = session
        self.url = url
        self.callback = callback
        self.presentationContextProvider = presentationContextProvider
    }
}

private func authservicesBuildWebAuthenticationSessionPayload(
    _ handle: WebAuthSessionHandle
) -> AuthServicesWebAuthenticationSessionPayload {
    let additionalHeaderFields: [String: String]?
    if #available(macOS 14.4, *) {
        additionalHeaderFields = handle.session.additionalHeaderFields
    } else {
        additionalHeaderFields = nil
    }
    return AuthServicesWebAuthenticationSessionPayload(
        url: handle.url,
        callback: handle.callback,
        prefersEphemeralWebBrowserSession: handle.session.prefersEphemeralWebBrowserSession,
        additionalHeaderFields: additionalHeaderFields,
        canStart: handle.session.canStart,
        usesPresentationContextProvider: true
    )
}

@available(macOS 14.4, *)
private func authservicesMakeWebAuthenticationCallback(
    from payload: AuthServicesWebAuthenticationCallbackPayload
) throws -> ASWebAuthenticationSession.Callback {
    switch payload.kind {
    case "custom_scheme":
        guard let scheme = payload.scheme else {
            throw AuthServicesBridgeError.invalidArgument("custom scheme callbacks require a scheme")
        }
        return .customScheme(scheme)
    case "https":
        guard let host = payload.host else {
            throw AuthServicesBridgeError.invalidArgument("https callbacks require a host")
        }
        return .https(host: host, path: payload.path ?? "")
    default:
        throw AuthServicesBridgeError.invalidArgument("unknown web-auth callback kind: \(payload.kind)")
    }
}

private func authservicesCreateWebAuthenticationSession(
    from payload: AuthServicesWebAuthenticationSessionPayload,
    refcon: UnsafeMutableRawPointer?,
    onComplete: @escaping @convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<CChar>?,
        Int32,
        UnsafeMutablePointer<CChar>?
    ) -> Void
) throws -> WebAuthSessionHandle {
    guard let url = URL(string: payload.url) else {
        throw AuthServicesBridgeError.invalidArgument("invalid URL")
    }
    let callback = payload.callback
    let session: ASWebAuthenticationSession
    if let callback, callback.kind == "https" {
        guard #available(macOS 14.4, *) else {
            throw AuthServicesBridgeError.notSupported(
                "https callbacks require ASWebAuthenticationSession.Callback on macOS 14.4"
            )
        }
        session = ASWebAuthenticationSession(
            url: url,
            callback: try authservicesMakeWebAuthenticationCallback(from: callback)
        ) { callbackURL, error in
            if let error {
                onComplete(refcon, nil, authservicesStatus(for: error), authservicesCString(error.localizedDescription))
            } else {
                onComplete(refcon, authservicesCString(callbackURL?.absoluteString ?? ""), AUTHSERVICES_OK, nil)
            }
        }
    } else {
        let scheme = callback?.scheme
        session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme) { callbackURL, error in
            if let error {
                onComplete(refcon, nil, authservicesStatus(for: error), authservicesCString(error.localizedDescription))
            } else {
                onComplete(refcon, authservicesCString(callbackURL?.absoluteString ?? ""), AUTHSERVICES_OK, nil)
            }
        }
    }
    session.prefersEphemeralWebBrowserSession = payload.prefersEphemeralWebBrowserSession
    if let additionalHeaderFields = payload.additionalHeaderFields, !additionalHeaderFields.isEmpty {
        guard #available(macOS 14.4, *) else {
            throw AuthServicesBridgeError.notSupported(
                "ASWebAuthenticationSession.additionalHeaderFields requires macOS 14.4"
            )
        }
        session.additionalHeaderFields = additionalHeaderFields
    }
    let presentationContextProvider = WebAuthSessionPresentationContextProvider()
    session.presentationContextProvider = presentationContextProvider
    return WebAuthSessionHandle(
        session: session,
        url: payload.url,
        callback: payload.callback,
        presentationContextProvider: presentationContextProvider
    )
}

@_cdecl("authservices_web_auth_session_create")
public func authservices_web_auth_session_create(
    _ urlString: UnsafePointer<CChar>?,
    _ callbackScheme: UnsafePointer<CChar>?,
    _ refcon: UnsafeMutableRawPointer?,
    _ onComplete: (@convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<CChar>?,
        Int32,
        UnsafeMutablePointer<CChar>?
    ) -> Void)?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard let urlString, let onComplete else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument(
                "url_string and on_complete callback are required"
            )
        )
        return nil
    }
    let payload = AuthServicesWebAuthenticationSessionPayload(
        url: String(cString: urlString),
        callback: callbackScheme.map {
            AuthServicesWebAuthenticationCallbackPayload(
                kind: "custom_scheme",
                scheme: String(cString: $0),
                host: nil,
                path: nil
            )
        },
        prefersEphemeralWebBrowserSession: false,
        additionalHeaderFields: nil,
        canStart: false,
        usesPresentationContextProvider: true
    )
    do {
        return authservices_retain(
            try authservicesCreateWebAuthenticationSession(
                from: payload,
                refcon: refcon,
                onComplete: onComplete
            )
        )
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_web_auth_session_create_from_json")
public func authservices_web_auth_session_create_from_json(
    _ payloadJson: UnsafePointer<CChar>?,
    _ refcon: UnsafeMutableRawPointer?,
    _ onComplete: (@convention(c) (
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<CChar>?,
        Int32,
        UnsafeMutablePointer<CChar>?
    ) -> Void)?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard let onComplete else {
        authservicesPopulateError(
            outError,
            with: AuthServicesBridgeError.invalidArgument("on_complete callback is required")
        )
        return nil
    }
    do {
        let payload = try authservicesDecodeJSON(
            payloadJson,
            as: AuthServicesWebAuthenticationSessionPayload.self
        )
        return authservices_retain(
            try authservicesCreateWebAuthenticationSession(
                from: payload,
                refcon: refcon,
                onComplete: onComplete
            )
        )
    } catch {
        authservicesPopulateError(outError, with: error)
        return nil
    }
}

@_cdecl("authservices_web_auth_session_copy_json")
public func authservices_web_auth_session_copy_json(
    _ ptr: UnsafeMutableRawPointer?
) -> UnsafeMutablePointer<CChar>? {
    guard let ptr else { return nil }
    let handle = authservices_borrow(ptr, as: WebAuthSessionHandle.self)
    return authservicesCopyJSON(authservicesBuildWebAuthenticationSessionPayload(handle))
}

@_cdecl("authservices_web_auth_session_start")
public func authservices_web_auth_session_start(
    _ ptr: UnsafeMutableRawPointer?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.invalidArgument("null web authentication session handle")
        )
    }
    let handle = authservices_borrow(ptr, as: WebAuthSessionHandle.self)
    var started = false
    if Thread.isMainThread {
        started = handle.session.start()
    } else {
        DispatchQueue.main.sync {
            started = handle.session.start()
        }
    }
    if started {
        return AUTHSERVICES_OK
    }
    return authservicesFail(
        outError,
        with: AuthServicesBridgeError.unknown("ASWebAuthenticationSession failed to start")
    )
}

@_cdecl("authservices_web_auth_session_cancel")
public func authservices_web_auth_session_cancel(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    let handle = authservices_borrow(ptr, as: WebAuthSessionHandle.self)
    DispatchQueue.main.async {
        handle.session.cancel()
    }
}

@_cdecl("authservices_web_auth_session_release")
public func authservices_web_auth_session_release(_ ptr: UnsafeMutableRawPointer?) {
    guard let ptr else { return }
    authservices_release(ptr)
}

@_cdecl("authservices_web_auth_callback_matches_url")
public func authservices_web_auth_callback_matches_url(
    _ callbackJson: UnsafePointer<CChar>?,
    _ urlString: UnsafePointer<CChar>?,
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let payload = try authservicesDecodeJSON(
            callbackJson,
            as: AuthServicesWebAuthenticationCallbackPayload.self
        )
        guard let urlString, let url = URL(string: String(cString: urlString)) else {
            throw AuthServicesBridgeError.invalidArgument("url_string must contain a valid URL")
        }
        if #available(macOS 14.4, *) {
            return try authservicesMakeWebAuthenticationCallback(from: payload).matchesURL(url) ? 1 : 0
        }
        switch payload.kind {
        case "custom_scheme":
            return url.scheme == payload.scheme ? 1 : 0
        default:
            throw AuthServicesBridgeError.notSupported(
                "ASWebAuthenticationSession.Callback requires macOS 14.4"
            )
        }
    } catch {
        authservicesPopulateError(outError, with: error)
        return -1
    }
}
