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

import Vapor
import Fluent

public protocol PassKitDelegate: class {
    /// Should return a `URL` which points to the template data for the pass.
    ///
    /// The URL should point to a directory containing all the images and
    /// localizations for the generated pkpass archive but should *not* contain any of these items:
    ///  - manifest.json
    ///  - pass.json
    ///  - signature
    /// - Parameters:
    ///   - pass: The pass data from the SQL server.
    ///   - db: The SQL database to query against.
    ///
    /// ### Note ###
    /// Be sure to use the `URL(fileURLWithPath:isDirectory:)` constructor.
    func template<P: PassKitPass>(for: P, db: Database) -> EventLoopFuture<URL>

    /// Generates the SSL `signature` file.
    ///
    /// If you need to implement custom S/Mime signing you can use this
    /// method to do so.  You must generate a detached DER signature of the
    /// `manifest.json` file.
    /// - Parameter root: The location of the `manifest.json` and where to write the `signature` to.
    /// - Returns: Return `true` if you generated a custom `signature`, otherwise `false`.
    func generateSignatureFile(in root: URL) -> Bool

    /// Encode the pass into JSON.
    ///
    /// This method should generate the entire pass JSON. You are provided with
    /// the pass data from the SQL database and you should return a properly
    /// formatted pass file encoding.
    /// - Parameters:
    ///   - pass: The pass data from the SQL server
    ///   - db: The SQL database to query against.
    ///   - encoder: The `JSONEncoder` which you should use.
    /// - See: [Understanding the Keys](https://developer.apple.com/library/archive/documentation/UserExperience/Reference/PassKit_Bundle/Chapters/Introduction.html)
    func encode<P: PassKitPass>(pass: P, db: Database, encoder: JSONEncoder) -> EventLoopFuture<Data>

    /// Should return a `URL` which points to the template data for the pass.
    ///
    /// The URL should point to a directory containing the files specified by these keys:
    /// - wwdrCertificate
    /// - pemCertificate
    /// - pemPrivateKey
    ///
    /// ### Note ###
    /// Be sure to use the `URL(fileURLWithPath:isDirectory:)` initializer!
    var sslSigningFilesDirectory: URL { get }

    /// The location of the `openssl` command as a file URL.
    /// - Note: Be sure to use the `URL(fileURLWithPath:)` constructor.
    var sslBinary: URL { get }

    /// The name of Apple's WWDR.pem certificate as contained in `sslSigningFiles` path.
    ///
    /// Defaults to `WWDR.pem`
    var wwdrCertificate: String { get }

    /// The name of the PEM Certificate for signing the pass as contained in `sslSigningFiles` path.
    ///
    /// Defaults to `passcertificate.pem`
    var pemCertificate: String { get }

    /// The name of the PEM Certificate's private key for signing the pass as contained in `sslSigningFiles` path.
    ///
    /// Defaults to `passkey.pem`
    var pemPrivateKey: String { get }

    /// The password to the private key file.
    var pemPrivateKeyPassword: String { get }
}

public extension PassKitDelegate {
    var wwdrCertificate: String {
        get { return "WWDR.pem" }
    }

    var pemCertificate: String {
        get { return "passcertificate.pem" }
    }

    var pemPrivateKey: String {
        get { return "passkey.pem" }
    }

    var sslBinary: URL {
        get { return URL(fileURLWithPath: "/usr/bin/openssl") }
    }

    func generateSignatureFile(in root: URL) -> Bool {
        return false
    }
}