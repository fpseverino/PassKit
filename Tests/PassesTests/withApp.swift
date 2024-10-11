import FluentKit
import FluentSQLiteDriver
import WalletKit
import Passes
import Testing
import Vapor
import Zip

func withApp(
    delegate: some PassesDelegate,
    isEncrypted: Bool = false,
    _ body: (Application, PassesService<PassData>) async throws -> Void
) async throws {
    let app = try await Application.make(.testing)
    try #require(isLoggingConfigured)

    app.databases.use(.sqlite(.memory), as: .sqlite)
    PassesService<PassData>.register(migrations: app.migrations)
    app.migrations.add(CreatePassData())
    let passesService = try PassesService<PassData>(
        app: app,
        delegate: delegate,
        dbID: .sqlite,
        signingFilesDirectory: "\(FileManager.default.currentDirectoryPath)/Tests/Certificates/",
        pemCertificate: isEncrypted ? "encryptedcert.pem" : "certificate.pem",
        pemPrivateKey: isEncrypted ? "encryptedkey.pem" : "key.pem",
        pemPrivateKeyPassword: isEncrypted ? "password" : nil,
        pushRoutesMiddleware: SecretMiddleware(secret: "foo"),
        logger: app.logger
    )
    try await app.autoMigrate()
    Zip.addCustomFileExtension("pkpass")

    try await body(app, passesService)

    try await app.autoRevert()
    try await app.asyncShutdown()
}
