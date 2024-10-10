//
//  OrdersDelegate.swift
//  PassKit
//
//  Created by Francesco Paolo Severino on 01/07/24.
//

import FluentKit
import Foundation

/// The delegate which is responsible for generating the order files.
public protocol OrdersDelegate: AnyObject, Sendable {
    /// Should return a URL path string which points to the template data for the order.
    ///
    /// The path should point to a directory containing all the images and localizations for the generated `.order` archive
    /// but should *not* contain any of these items:
    ///  - `manifest.json`
    ///  - `order.json`
    ///  - `signature`
    ///
    /// - Parameters:
    ///   - order: The order data from the SQL server.
    ///   - db: The SQL database to query against.
    ///
    /// - Returns: A URL path string which points to the template data for the order.
    func template<O: OrderModel>(for order: O, db: any Database) async throws -> String

    /// Generates the SSL `signature` file.
    ///
    /// If you need to implement custom S/Mime signing you can use this
    /// method to do so. You must generate a detached DER signature of the `manifest.json` file.
    ///
    /// - Parameter root: The location of the `manifest.json` and where to write the `signature` to.
    /// - Returns: Return `true` if you generated a custom `signature`, otherwise `false`.
    func generateSignatureFile(in root: URL) -> Bool

    /// Encode the order into JSON.
    ///
    /// This method should generate the entire order JSON. You are provided with
    /// the order data from the SQL database and you should return a properly
    /// formatted order file encoding.
    ///
    /// - Parameters:
    ///   - order: The order data from the SQL server
    ///   - db: The SQL database to query against.
    ///   - encoder: The `JSONEncoder` which you should use.
    /// - Returns: The encoded order JSON data.
    ///
    /// > Tip: See the [`Order`](https://developer.apple.com/documentation/walletorders/order) object to understand the keys.
    func encode<O: OrderModel>(
        order: O, db: any Database, encoder: JSONEncoder
    ) async throws -> Data
}

extension OrdersDelegate {
    public func generateSignatureFile(in root: URL) -> Bool {
        return false
    }
}
