/// Copyright 2020 Gargoyle Software, LLC
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// Notwithstanding the foregoing, you may not use, copy, modify, merge, publish,
/// distribute, sublicense, create a derivative work, and/or sell copies of the
/// Software in any work that is designed, intended, or marketed for pedagogical or
/// instructional purposes related to programming, coding, application development,
/// or information technology.  Permission for such use, copying, modification,
/// merger, publication, distribution, sublicensing, creation of derivative works,
/// or sale is expressly withheld.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
/// THE SOFTWARE.

import FluentKit
import Vapor

/// The main class that handles PassKit passes.
public final class PassesService<PD: PassDataModel>: Sendable where PD.PassType == Pass {
    private let service: PassesServiceCustom<PD, Pass, UserPersonalization, PassesDevice, PassesRegistration, PassesErrorLog>

    /// Initializes the service and registers all the routes required for PassKit to work.
    ///
    /// - Parameters:
    ///   - app: The `Vapor.Application` to use in route handlers and APNs.
    ///   - delegate: The ``PassesDelegate`` to use for pass generation.
    ///   - dbID: The `DatabaseID` on which to register the middleware.
    ///   - signingFilesDirectory: A URL path string which points to the WWDR certificate and the PEM certificate and private key.
    ///   - wwdrCertificate: The name of Apple's WWDR.pem certificate as contained in `signingFilesDirectory` path.
    ///   - pemCertificate: The name of the PEM Certificate for signing passes as contained in `signingFilesDirectory` path.
    ///   - pemPrivateKey: The name of the PEM Certificate's private key for signing passes as contained in `signingFilesDirectory` path.
    ///   - pemPrivateKeyPassword: The password of the PEM private key file.
    ///   - sslBinary: The location of the `openssl` command as a file path.
    ///   - pushRoutesMiddleware: The `Middleware` to use for push notification routes. If `nil`, push routes will not be registered.
    ///   - logger: The `Logger` to use.
    public init(
        app: Application,
        delegate: any PassesDelegate,
        dbID: DatabaseID,
        signingFilesDirectory: String,
        wwdrCertificate: String = "WWDR.pem",
        pemCertificate: String = "certificate.pem",
        pemPrivateKey: String = "key.pem",
        pemPrivateKeyPassword: String? = nil,
        sslBinary: String = "/usr/bin/openssl",
        pushRoutesMiddleware: (any Middleware)? = nil,
        logger: Logger? = nil
    ) throws {
        self.service = try .init(
            app: app,
            delegate: delegate,
            dbID: dbID,
            signingFilesDirectory: signingFilesDirectory,
            wwdrCertificate: wwdrCertificate,
            pemCertificate: pemCertificate,
            pemPrivateKey: pemPrivateKey,
            pemPrivateKeyPassword: pemPrivateKeyPassword,
            sslBinary: sslBinary,
            pushRoutesMiddleware: pushRoutesMiddleware,
            logger: logger
        )
    }

    /// Generates the pass content bundle for a given pass.
    ///
    /// - Parameters:
    ///   - pass: The pass to generate the content for.
    ///   - db: The `Database` to use.
    /// - Returns: The generated pass content as `Data`.
    public func generatePassContent(for pass: Pass, on db: any Database) async throws -> Data {
        try await service.generatePassContent(for: pass, on: db)
    }

    /// Generates a bundle of passes to enable your user to download multiple passes at once.
    ///
    /// > Note: You can have up to 10 passes or 150 MB for a bundle of passes.
    ///
    /// > Important: Bundles of passes are supported only in Safari. You can't send the bundle via AirDrop or other methods.
    ///
    /// - Parameters:
    ///   - passes: The passes to include in the bundle.
    ///   - db: The `Database` to use.
    /// - Returns: The bundle of passes as `Data`.
    public func generatePassesContent(for passes: [Pass], on db: any Database) async throws -> Data {
        try await service.generatePassesContent(for: passes, on: db)
    }

    /// Sends push notifications for a given pass.
    ///
    /// - Parameters:
    ///   - pass: The pass to send the notifications for.
    ///   - db: The `Database` to use.
    public func sendPushNotifications(for pass: Pass, on db: any Database) async throws {
        try await service.sendPushNotifications(for: pass, on: db)
    }
}
