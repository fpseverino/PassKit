//
//  PassesServiceCustom.swift
//  PassKit
//
//  Created by Francesco Paolo Severino on 29/06/24.
//

import APNS
import APNSCore
import Fluent
import NIOSSL
import PassKit
import Vapor
import VaporAPNS
@_spi(CMS) import X509
import Zip

/// Class to handle ``PassesService``.
///
/// The generics should be passed in this order:
/// - Pass Type
/// - User Personalization Type
/// - Device Type
/// - Registration Type
/// - Error Log Type
public final class PassesServiceCustom<PD: PassDataModel, P, U, D, R: PassesRegistrationModel, E: ErrorLogModel>: Sendable
where PD.PassType == P, P == R.PassType, D == R.DeviceType, U == P.UserPersonalizationType {
    private unowned let app: Application
    private unowned let delegate: any PassesDelegate
    private let logger: Logger?
    private let signingFilesDirectory: URL
    private let wwdrCertificate: String
    private let pemCertificate: String
    private let pemPrivateKey: String
    private let pemPrivateKeyPassword: String?
    private let sslBinary: URL
    private let encoder = JSONEncoder()

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
        self.app = app
        self.delegate = delegate
        self.logger = logger
        self.signingFilesDirectory = URL(fileURLWithPath: signingFilesDirectory, isDirectory: true)
        self.wwdrCertificate = wwdrCertificate
        self.pemCertificate = pemCertificate
        self.pemPrivateKey = pemPrivateKey
        self.pemPrivateKeyPassword = pemPrivateKeyPassword
        self.sslBinary = URL(fileURLWithPath: sslBinary)

        app.databases.middleware.use(self, on: dbID)

        let privateKeyPath = URL(fileURLWithPath: self.pemPrivateKey, relativeTo: self.signingFilesDirectory).path
        guard FileManager.default.fileExists(atPath: privateKeyPath) else {
            throw PassesError.pemPrivateKeyMissing
        }
        let pemPath = URL(fileURLWithPath: self.pemCertificate, relativeTo: self.signingFilesDirectory).path
        guard FileManager.default.fileExists(atPath: pemPath) else {
            throw PassesError.pemCertificateMissing
        }
        let apnsConfig: APNSClientConfiguration
        if let password = self.pemPrivateKeyPassword {
            apnsConfig = APNSClientConfiguration(
                authenticationMethod: try .tls(
                    privateKey: .privateKey(
                        NIOSSLPrivateKey(file: privateKeyPath, format: .pem) { closure in
                            closure(password.utf8)
                        }),
                    certificateChain: NIOSSLCertificate.fromPEMFile(pemPath).map {
                        .certificate($0)
                    }
                ),
                environment: .production
            )
        } else {
            apnsConfig = APNSClientConfiguration(
                authenticationMethod: try .tls(
                    privateKey: .privateKey(NIOSSLPrivateKey(file: privateKeyPath, format: .pem)),
                    certificateChain: NIOSSLCertificate.fromPEMFile(pemPath).map {
                        .certificate($0)
                    }
                ),
                environment: .production
            )
        }
        app.apns.containers.use(
            apnsConfig,
            eventLoopGroupProvider: .shared(app.eventLoopGroup),
            responseDecoder: JSONDecoder(),
            requestEncoder: self.encoder,
            as: .init(string: "passes"),
            isDefault: false
        )

        let v1 = app.grouped("api", "passes", "v1")
        v1.get(
            "devices", ":deviceLibraryIdentifier", "registrations", "\(PD.typeIdentifier)",
            use: { try await self.passesForDevice(req: $0) }
        )
        v1.post("log", use: { try await self.logError(req: $0) })
        v1.post(
            "passes", "\(PD.typeIdentifier)", ":passSerial", "personalize",
            use: { try await self.personalizedPass(req: $0) }
        )

        let v1auth = v1.grouped(ApplePassMiddleware<P>())
        v1auth.post(
            "devices", ":deviceLibraryIdentifier", "registrations", "\(PD.typeIdentifier)",
            ":passSerial", use: { try await self.registerDevice(req: $0) }
        )
        v1auth.get("passes", "\(PD.typeIdentifier)", ":passSerial", use: { try await self.latestVersionOfPass(req: $0) })
        v1auth.delete(
            "devices", ":deviceLibraryIdentifier", "registrations", "\(PD.typeIdentifier)",
            ":passSerial", use: { try await self.unregisterDevice(req: $0) }
        )

        if let pushRoutesMiddleware {
            let pushAuth = v1.grouped(pushRoutesMiddleware)
            pushAuth.post("push", "\(PD.typeIdentifier)", ":passSerial", use: { try await self.pushUpdatesForPass(req: $0) })
            pushAuth.get("push", "\(PD.typeIdentifier)", ":passSerial", use: { try await self.tokensForPassUpdate(req: $0) })
        }
    }
}

// MARK: - API Routes
extension PassesServiceCustom {
    func registerDevice(req: Request) async throws -> HTTPStatus {
        logger?.debug("Called register device")

        let pushToken: String
        do {
            pushToken = try req.content.decode(RegistrationDTO.self).pushToken
        } catch {
            throw Abort(.badRequest)
        }

        guard let serial = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        let deviceLibraryIdentifier = req.parameters.get("deviceLibraryIdentifier")!
        guard
            let pass = try await P.query(on: req.db)
                .filter(\._$typeIdentifier == PD.typeIdentifier)
                .filter(\._$id == serial)
                .first()
        else {
            throw Abort(.notFound)
        }

        let device = try await D.query(on: req.db)
            .filter(\._$deviceLibraryIdentifier == deviceLibraryIdentifier)
            .filter(\._$pushToken == pushToken)
            .first()
        if let device = device {
            return try await Self.createRegistration(device: device, pass: pass, db: req.db)
        } else {
            let newDevice = D(deviceLibraryIdentifier: deviceLibraryIdentifier, pushToken: pushToken)
            try await newDevice.create(on: req.db)
            return try await Self.createRegistration(device: newDevice, pass: pass, db: req.db)
        }
    }

    private static func createRegistration(
        device: D,
        pass: P,
        db: any Database
    ) async throws -> HTTPStatus {
        let r = try await R.for(
            deviceLibraryIdentifier: device.deviceLibraryIdentifier,
            typeIdentifier: PD.typeIdentifier,
            on: db
        )
        .filter(P.self, \._$id == pass.requireID())
        .first()
        // If the registration already exists, docs say to return 200 OK
        if r != nil { return .ok }

        let registration = R()
        registration._$pass.id = try pass.requireID()
        registration._$device.id = try device.requireID()
        try await registration.create(on: db)
        return .created
    }

    func passesForDevice(req: Request) async throws -> PassesForDeviceDTO {
        logger?.debug("Called passesForDevice")

        let deviceLibraryIdentifier = req.parameters.get("deviceLibraryIdentifier")!

        var query = R.for(
            deviceLibraryIdentifier: deviceLibraryIdentifier,
            typeIdentifier: PD.typeIdentifier,
            on: req.db
        )
        if let since: TimeInterval = req.query["passesUpdatedSince"] {
            let when = Date(timeIntervalSince1970: since)
            query = query.filter(P.self, \._$updatedAt > when)
        }

        let registrations = try await query.all()
        guard !registrations.isEmpty else {
            throw Abort(.noContent)
        }

        var serialNumbers: [String] = []
        var maxDate = Date.distantPast
        for registration in registrations {
            let pass = registration.pass
            try serialNumbers.append(pass.requireID().uuidString)
            if let updatedAt = pass.updatedAt, updatedAt > maxDate {
                maxDate = updatedAt
            }
        }

        return PassesForDeviceDTO(with: serialNumbers, maxDate: maxDate)
    }

    func latestVersionOfPass(req: Request) async throws -> Response {
        logger?.debug("Called latestVersionOfPass")

        var ifModifiedSince: TimeInterval = 0
        if let header = req.headers[.ifModifiedSince].first, let ims = TimeInterval(header) {
            ifModifiedSince = ims
        }

        guard let id = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        guard
            let pass = try await P.query(on: req.db)
                .filter(\._$id == id)
                .filter(\._$typeIdentifier == PD.typeIdentifier)
                .first()
        else {
            throw Abort(.notFound)
        }

        guard ifModifiedSince < pass.updatedAt?.timeIntervalSince1970 ?? 0 else {
            throw Abort(.notModified)
        }

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/vnd.apple.pkpass")
        headers.lastModified = HTTPHeaders.LastModified(pass.updatedAt ?? Date.distantPast)
        headers.add(name: .contentTransferEncoding, value: "binary")
        return try await Response(
            status: .ok,
            headers: headers,
            body: Response.Body(data: self.generatePassContent(for: pass, on: req.db))
        )
    }

    func unregisterDevice(req: Request) async throws -> HTTPStatus {
        logger?.debug("Called unregisterDevice")

        guard let passId = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        let deviceLibraryIdentifier = req.parameters.get("deviceLibraryIdentifier")!

        guard
            let r = try await R.for(
                deviceLibraryIdentifier: deviceLibraryIdentifier,
                typeIdentifier: PD.typeIdentifier,
                on: req.db
            )
            .filter(P.self, \._$id == passId)
            .first()
        else {
            throw Abort(.notFound)
        }
        try await r.delete(on: req.db)
        return .ok
    }

    func logError(req: Request) async throws -> HTTPStatus {
        logger?.debug("Called logError")

        let body: ErrorLogDTO
        do {
            body = try req.content.decode(ErrorLogDTO.self)
        } catch {
            throw Abort(.badRequest)
        }

        guard !body.logs.isEmpty else {
            throw Abort(.badRequest)
        }

        try await body.logs.map(E.init(message:)).create(on: req.db)
        return .ok
    }

    func personalizedPass(req: Request) async throws -> Response {
        logger?.debug("Called personalizedPass")

        guard let id = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        guard
            let pass = try await P.query(on: req.db)
                .filter(\._$id == id)
                .filter(\._$typeIdentifier == PD.typeIdentifier)
                .first()
        else {
            throw Abort(.notFound)
        }

        let userInfo = try req.content.decode(PersonalizationDictionaryDTO.self)

        let userPersonalization = U()
        userPersonalization.fullName = userInfo.requiredPersonalizationInfo.fullName
        userPersonalization.givenName = userInfo.requiredPersonalizationInfo.givenName
        userPersonalization.familyName = userInfo.requiredPersonalizationInfo.familyName
        userPersonalization.emailAddress = userInfo.requiredPersonalizationInfo.emailAddress
        userPersonalization.postalCode = userInfo.requiredPersonalizationInfo.postalCode
        userPersonalization.isoCountryCode = userInfo.requiredPersonalizationInfo.isoCountryCode
        userPersonalization.phoneNumber = userInfo.requiredPersonalizationInfo.phoneNumber
        try await userPersonalization.create(on: req.db)

        pass._$userPersonalization.id = try userPersonalization.requireID()
        try await pass.update(on: req.db)

        let tmp = FileManager.default.temporaryDirectory
        let root = tmp.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { _ = try? FileManager.default.removeItem(at: root) }

        guard let token = userInfo.personalizationToken.data(using: .utf8) else {
            throw Abort(.internalServerError)
        }
        let signature: Data
        if let password = self.pemPrivateKeyPassword {
            guard FileManager.default.fileExists(atPath: self.sslBinary.path) else {
                throw PassesError.opensslBinaryMissing
            }

            let tokenURL = root.appendingPathComponent("personalizationToken")
            try token.write(to: tokenURL)

            let proc = Process()
            proc.currentDirectoryURL = self.signingFilesDirectory
            proc.executableURL = self.sslBinary
            proc.arguments = [
                "smime", "-binary", "-sign",
                "-certfile", self.wwdrCertificate,
                "-signer", self.pemCertificate,
                "-inkey", self.pemPrivateKey,
                "-in", tokenURL.path,
                "-out", root.appendingPathComponent("signature").path,
                "-outform", "DER",
                "-passin", "pass:\(password)",
            ]
            try proc.run()
            proc.waitUntilExit()
            signature = try Data(contentsOf: root.appendingPathComponent("signature"))
        } else {
            let signatureBytes = try CMS.sign(
                token,
                signatureAlgorithm: .sha256WithRSAEncryption,
                additionalIntermediateCertificates: [
                    Certificate(
                        pemEncoded: String(
                            contentsOf: self.signingFilesDirectory
                                .appendingPathComponent(self.wwdrCertificate)
                        )
                    )
                ],
                certificate: Certificate(
                    pemEncoded: String(
                        contentsOf: self.signingFilesDirectory
                            .appendingPathComponent(self.pemCertificate)
                    )
                ),
                privateKey: .init(
                    pemEncoded: String(
                        contentsOf: self.signingFilesDirectory
                            .appendingPathComponent(self.pemPrivateKey)
                    )
                ),
                signingTime: Date()
            )
            signature = Data(signatureBytes)
        }

        var headers = HTTPHeaders()
        headers.add(name: .contentType, value: "application/octet-stream")
        headers.add(name: .contentTransferEncoding, value: "binary")
        return Response(status: .ok, headers: headers, body: Response.Body(data: signature))
    }

    // MARK: - Push Routes
    func pushUpdatesForPass(req: Request) async throws -> HTTPStatus {
        logger?.debug("Called pushUpdatesForPass")

        guard let id = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }
        guard let pass = try await P.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        try await sendPushNotifications(for: pass, on: req.db)
        return .noContent
    }

    func tokensForPassUpdate(req: Request) async throws -> [String] {
        logger?.debug("Called tokensForPassUpdate")

        guard let id = req.parameters.get("passSerial", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        return try await Self.registrationsForPass(id: id, on: req.db).map { $0.device.pushToken }
    }
}

// MARK: - Push Notifications
extension PassesServiceCustom {
    /// Sends push notifications for a given pass.
    ///
    /// - Parameters:
    ///   - pass: The pass to send the notifications for.
    ///   - db: The `Database` to use.
    public func sendPushNotifications(for pass: P, on db: any Database) async throws {
        let registrations = try await Self.registrationsForPass(id: pass.requireID(), on: db)
        for registration in registrations {
            let backgroundNotification = APNSBackgroundNotification(
                expiration: .immediately,
                topic: PD.typeIdentifier,
                payload: EmptyPayload()
            )
            do {
                try await app.apns.client(.init(string: "passes")).sendBackgroundNotification(
                    backgroundNotification,
                    deviceToken: registration.device.pushToken
                )
            } catch let error as APNSCore.APNSError where error.reason == .badDeviceToken {
                try await registration.device.delete(on: db)
                try await registration.delete(on: db)
            }
        }
    }

    static func registrationsForPass(id: UUID, on db: any Database) async throws -> [R] {
        // This could be done by enforcing the caller to have a Siblings property wrapper,
        // but there's not really any value to forcing that on them when we can just do the query ourselves like this.
        try await R.query(on: db)
            .join(parent: \._$pass)
            .join(parent: \._$device)
            .with(\._$pass)
            .with(\._$device)
            .filter(P.self, \._$typeIdentifier == PD.typeIdentifier)
            .filter(P.self, \._$id == id)
            .all()
    }
}

// MARK: - pkpass file generation
extension PassesServiceCustom {
    private static func generateManifestFile(using encoder: JSONEncoder, in root: URL) throws -> Data {
        var manifest: [String: String] = [:]
        let paths = try FileManager.default.subpathsOfDirectory(atPath: root.path)
        for relativePath in paths {
            let file = URL(fileURLWithPath: relativePath, relativeTo: root)
            guard !file.hasDirectoryPath else { continue }
            let data = try Data(contentsOf: file)
            let hash = Insecure.SHA1.hash(data: data)
            manifest[relativePath] = hash.map { "0\(String($0, radix: 16))".suffix(2) }.joined()
        }
        let data = try encoder.encode(manifest)
        try data.write(to: root.appendingPathComponent("manifest.json"))
        return data
    }

    private func generateSignatureFile(for manifest: Data, in root: URL) throws {
        // If the caller's delegate generated a file we don't have to do it.
        if delegate.generateSignatureFile(in: root) { return }

        // Swift Crypto doesn't support encrypted PEM private keys, so we have to use OpenSSL for that.
        if let password = self.pemPrivateKeyPassword {
            guard FileManager.default.fileExists(atPath: self.sslBinary.path) else {
                throw PassesError.opensslBinaryMissing
            }

            let proc = Process()
            proc.currentDirectoryURL = self.signingFilesDirectory
            proc.executableURL = self.sslBinary
            proc.arguments = [
                "smime", "-binary", "-sign",
                "-certfile", self.wwdrCertificate,
                "-signer", self.pemCertificate,
                "-inkey", self.pemPrivateKey,
                "-in", root.appendingPathComponent("manifest.json").path,
                "-out", root.appendingPathComponent("signature").path,
                "-outform", "DER",
                "-passin", "pass:\(password)",
            ]
            try proc.run()
            proc.waitUntilExit()
            return
        }

        let signature = try CMS.sign(
            manifest,
            signatureAlgorithm: .sha256WithRSAEncryption,
            additionalIntermediateCertificates: [
                Certificate(
                    pemEncoded: String(
                        contentsOf: self.signingFilesDirectory
                            .appendingPathComponent(self.wwdrCertificate)
                    )
                )
            ],
            certificate: Certificate(
                pemEncoded: String(
                    contentsOf: self.signingFilesDirectory
                        .appendingPathComponent(self.pemCertificate)
                )
            ),
            privateKey: .init(
                pemEncoded: String(
                    contentsOf: self.signingFilesDirectory
                        .appendingPathComponent(self.pemPrivateKey)
                )
            ),
            signingTime: Date()
        )
        try Data(signature).write(to: root.appendingPathComponent("signature"))
    }

    /// Generates the pass content bundle for a given pass.
    ///
    /// - Parameters:
    ///   - pass: The pass to generate the content for.
    ///   - db: The `Database` to use.
    /// - Returns: The generated pass content as `Data`.
    public func generatePassContent(for pass: P, on db: any Database) async throws -> Data {
        let templateDirectory = URL(fileURLWithPath: try await delegate.template(for: pass, db: db), isDirectory: true)
        guard (try? templateDirectory.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false else {
            throw PassesError.templateNotDirectory
        }
        var files = try FileManager.default.contentsOfDirectory(at: templateDirectory, includingPropertiesForKeys: nil)

        let tmp = FileManager.default.temporaryDirectory
        let root = tmp.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.copyItem(at: templateDirectory, to: root)
        defer { _ = try? FileManager.default.removeItem(at: root) }

        try await self.delegate.encode(pass: pass, db: db, encoder: self.encoder)
            .write(to: root.appendingPathComponent("pass.json"))

        // Pass Personalization
        if let encodedPersonalization = try await self.delegate.encodePersonalization(for: pass, db: db) {
            try encoder.encode(encodedPersonalization).write(to: root.appendingPathComponent("personalization.json"))
            files.append(URL(fileURLWithPath: "personalization.json", relativeTo: root))
        }

        try self.generateSignatureFile(
            for: Self.generateManifestFile(using: self.encoder, in: root),
            in: root
        )

        files.append(URL(fileURLWithPath: "pass.json", relativeTo: root))
        files.append(URL(fileURLWithPath: "manifest.json", relativeTo: root))
        files.append(URL(fileURLWithPath: "signature", relativeTo: root))
        return try Data(contentsOf: Zip.quickZipFiles(files, fileName: UUID().uuidString))
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
    public func generatePassesContent(for passes: [P], on db: any Database) async throws -> Data {
        guard passes.count > 1 && passes.count <= 10 else {
            throw PassesError.invalidNumberOfPasses
        }

        let tmp = FileManager.default.temporaryDirectory
        let root = tmp.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { _ = try? FileManager.default.removeItem(at: root) }

        var files: [URL] = []
        for (i, pass) in passes.enumerated() {
            let name = "pass\(i).pkpass"
            try await self.generatePassContent(for: pass, on: db).write(to: root.appendingPathComponent(name))
            files.append(URL(fileURLWithPath: name, relativeTo: root))
        }
        return try Data(contentsOf: Zip.quickZipFiles(files, fileName: UUID().uuidString))
    }
}
