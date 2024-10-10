import FluentKit
import Orders
import Vapor

final class EncryptedOrdersDelegate: OrdersDelegate {
    func encode<O: OrderModel>(
        order: O, db: any Database, encoder: JSONEncoder
    ) async throws -> Data {
        guard
            let orderData = try await OrderData.query(on: db)
                .filter(\.$order.$id == order.requireID())
                .with(\.$order)
                .first()
        else {
            throw Abort(.internalServerError)
        }
        guard let data = try? encoder.encode(OrderJSONData(data: orderData, order: orderData.order))
        else {
            throw Abort(.internalServerError)
        }
        return data
    }

    func template<O: OrderModel>(for: O, db: any Database) async throws -> String {
        "\(FileManager.default.currentDirectoryPath)/Tests/OrdersTests/Templates/"
    }
}
