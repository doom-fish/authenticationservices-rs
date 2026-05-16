import Foundation
import AuthenticationServices

@_cdecl("authservices_settings_helper_is_supported")
public func authservices_settings_helper_is_supported() -> Int32 {
    if #available(macOS 14.0, *) {
        return 1
    }
    return 0
}

@_cdecl("authservices_settings_helper_open_credential_provider_app_settings")
public func authservices_settings_helper_open_credential_provider_app_settings(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.notSupported(
                "ASSettingsHelper.openCredentialProviderAppSettings requires macOS 14.0"
            )
        )
    }
    return authservicesBlockOnAsync(
        work: {
            try await ASSettingsHelper.openCredentialProviderAppSettings()
        },
        onSuccess: { (_: Void) in },
        onError: { error in authservicesPopulateError(outError, with: error) }
    )
}

@_cdecl("authservices_settings_helper_open_verification_code_app_settings")
public func authservices_settings_helper_open_verification_code_app_settings(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.notSupported(
                "ASSettingsHelper.openVerificationCodeAppSettings requires macOS 14.0"
            )
        )
    }
    return authservicesBlockOnAsync(
        work: {
            try await ASSettingsHelper.openVerificationCodeAppSettings()
        },
        onSuccess: { (_: Void) in },
        onError: { error in authservicesPopulateError(outError, with: error) }
    )
}

@_cdecl("authservices_settings_helper_request_to_turn_on_credential_provider_extension")
public func authservices_settings_helper_request_to_turn_on_credential_provider_extension(
    _ outError: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 15.0, *) else {
        return authservicesFail(
            outError,
            with: AuthServicesBridgeError.notSupported(
                "ASSettingsHelper.requestToTurnOnCredentialProviderExtension requires macOS 15.0"
            )
        )
    }
    return authservicesBlockOnAsync(
        work: {
            try await ASSettingsHelper.requestToTurnOnCredentialProviderExtension()
        },
        onSuccess: { (_: Void) in },
        onError: { error in authservicesPopulateError(outError, with: error) }
    )
}
