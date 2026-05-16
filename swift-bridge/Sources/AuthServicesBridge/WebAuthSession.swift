import Foundation
import AuthenticationServices

/// Opaque handle wrapping ASWebAuthenticationSession + delegate closure.
final class WebAuthSessionHandle {
    let session: ASWebAuthenticationSession
    init(session: ASWebAuthenticationSession) { self.session = session }
}

@_cdecl("authservices_web_auth_session_create")
public func authservices_web_auth_session_create(
    url_string: UnsafePointer<CChar>?,
    callback_scheme: UnsafePointer<CChar>?,
    refcon: UnsafeMutableRawPointer?,
    on_complete: (@convention(c) (UnsafeMutableRawPointer?, UnsafeMutablePointer<CChar>?, Int32, UnsafeMutablePointer<CChar>?) -> Void)?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard
        let urlStr = url_string.map({ String(cString: $0) }),
        let url = URL(string: urlStr)
    else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument("invalid URL"))
        return nil
    }
    guard let onComplete = on_complete else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument("on_complete callback is required"))
        return nil
    }
    let scheme = callback_scheme.map { String(cString: $0) }
    let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme) { callbackURL, error in
        if let error = error {
            let code = authservicesStatus(for: error)
            onComplete(refcon, nil, code, authservicesCString(error.localizedDescription))
        } else {
            let urlStr = callbackURL?.absoluteString ?? ""
            onComplete(refcon, authservicesCString(urlStr), AUTHSERVICES_OK, nil)
        }
    }
    session.prefersEphemeralWebBrowserSession = false
    let handle = WebAuthSessionHandle(session: session)
    return authservices_retain(handle)
}

@_cdecl("authservices_web_auth_session_start")
public func authservices_web_auth_session_start(
    _ ptr: UnsafeMutableRawPointer?,
    out_error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let ptr else {
        authservicesPopulateError(out_error, with: AuthServicesBridgeError.invalidArgument("null handle"))
        return AUTHSERVICES_INVALID_ARGUMENT
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
    if started { return AUTHSERVICES_OK }
    authservicesPopulateError(out_error, with: AuthServicesBridgeError.unknown("session failed to start"))
    return AUTHSERVICES_FRAMEWORK_ERROR
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
