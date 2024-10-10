import Fluent
import Passes
import Vapor

import struct Foundation.UUID

final class PassData: PassDataModel, @unchecked Sendable {
    static let schema = PassData.FieldKeys.schemaName

    static let typeIdentifier = "pass.com.vapor-community.PassKit"

    @ID(key: .id)
    var id: UUID?

    @Field(key: PassData.FieldKeys.title)
    var title: String

    @Parent(key: PassData.FieldKeys.passID)
    var pass: Pass

    init() {}

    init(id: UUID? = nil, title: String) {
        self.id = id
        self.title = title
    }
}

struct CreatePassData: AsyncMigration {
    func prepare(on database: any Database) async throws {
        try await database.schema(PassData.FieldKeys.schemaName)
            .id()
            .field(PassData.FieldKeys.title, .string, .required)
            .field(PassData.FieldKeys.passID, .uuid, .required, .references(Pass.schema, .id, onDelete: .cascade))
            .create()
    }

    func revert(on database: any Database) async throws {
        try await database.schema(PassData.FieldKeys.schemaName).delete()
    }
}

extension PassData {
    enum FieldKeys {
        static let schemaName = "pass_data"
        static let title = FieldKey(stringLiteral: "title")
        static let passID = FieldKey(stringLiteral: "pass_id")
    }
}

struct PassJSONData: PassJSON.Properties {
    let description: String
    let formatVersion = PassJSON.FormatVersion.v1
    let organizationName = "vapor-community"
    let passTypeIdentifier = PassData.typeIdentifier
    let serialNumber: String
    let teamIdentifier = "K6512ZA2S5"

    private let webServiceURL = "https://www.example.com/api/passes/"
    private let authenticationToken: String
    private let logoText = "Vapor Community"
    private let sharingProhibited = true
    let backgroundColor = "rgb(207, 77, 243)"
    let foregroundColor = "rgb(255, 255, 255)"

    let barcodes = Barcode(message: "test")
    struct Barcode: PassJSON.Barcodes {
        let format = PassJSON.BarcodeFormat.qr
        let message: String
        let messageEncoding = "iso-8859-1"
    }

    let boardingPass = Boarding(transitType: .air)
    struct Boarding: PassJSON.BoardingPass {
        let transitType: PassJSON.TransitType
        let headerFields: [PassField]
        let primaryFields: [PassField]
        let secondaryFields: [PassField]
        let auxiliaryFields: [PassField]
        let backFields: [PassField]

        struct PassField: PassJSON.PassFieldContent {
            let key: String
            let label: String
            let value: String
        }

        init(transitType: PassJSON.TransitType) {
            self.headerFields = [.init(key: "header", label: "Header", value: "Header")]
            self.primaryFields = [.init(key: "primary", label: "Primary", value: "Primary")]
            self.secondaryFields = [.init(key: "secondary", label: "Secondary", value: "Secondary")]
            self.auxiliaryFields = [.init(key: "auxiliary", label: "Auxiliary", value: "Auxiliary")]
            self.backFields = [.init(key: "back", label: "Back", value: "Back")]
            self.transitType = transitType
        }
    }

    init(data: PassData, pass: Pass) {
        self.description = data.title
        self.serialNumber = pass.id!.uuidString
        self.authenticationToken = pass.authenticationToken
    }
}
