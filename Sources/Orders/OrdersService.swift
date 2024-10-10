//
//  OrdersService.swift
//  PassKit
//
//  Created by Francesco Paolo Severino on 01/07/24.
//

import FluentKit
import Vapor

/// The main class that handles Wallet orders.
public final class OrdersService<OD: OrderDataModel>: Sendable where OD.OrderType == Order {
    private let service: OrdersServiceCustom<OD, Order, OrdersDevice, OrdersRegistration, OrdersErrorLog>

    /// Initializes the service and registers all the routes required for Apple Wallet to work.
    ///
    /// - Parameters:
    ///   - app: The `Vapor.Application` to use in route handlers and APNs.
    ///   - delegate: The ``OrdersDelegate`` to use for order generation.
    ///   - dbID: The `DatabaseID` on which to register the middleware.
    ///   - signingFilesDirectory: A URL path string which points to the WWDR certificate and the PEM certificate and private key.
    ///   - wwdrCertificate: The name of Apple's WWDR.pem certificate as contained in `signingFilesDirectory` path.
    ///   - pemCertificate: The name of the PEM Certificate for signing orders as contained in `signingFilesDirectory` path.
    ///   - pemPrivateKey: The name of the PEM Certificate's private key for signing orders as contained in `signingFilesDirectory` path.
    ///   - pemPrivateKeyPassword: The password of the PEM private key file.
    ///   - sslBinary: The location of the `openssl` command as a file path.
    ///   - pushRoutesMiddleware: The `Middleware` to use for push notification routes. If `nil`, push routes will not be registered.
    ///   - logger: The `Logger` to use.
    public init(
        app: Application,
        delegate: any OrdersDelegate,
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
        service = try .init(
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

    /// Generates the order content bundle for a given order.
    ///
    /// - Parameters:
    ///   - order: The order to generate the content for.
    ///   - db: The `Database` to use.
    /// - Returns: The generated order content.
    public func generateOrderContent(for order: Order, on db: any Database) async throws -> Data {
        try await service.generateOrderContent(for: order, on: db)
    }

    /// Adds the migrations for Wallet orders models.
    ///
    /// - Parameter migrations: The `Migrations` object to add the migrations to.
    public static func register(migrations: Migrations) {
        migrations.add(Order())
        migrations.add(OrdersDevice())
        migrations.add(OrdersRegistration())
        migrations.add(OrdersErrorLog())
    }

    /// Sends push notifications for a given order.
    ///
    /// - Parameters:
    ///   - order: The order to send the notifications for.
    ///   - db: The `Database` to use.
    public func sendPushNotifications(for order: Order, on db: any Database) async throws {
        try await service.sendPushNotifications(for: order, on: db)
    }
}
