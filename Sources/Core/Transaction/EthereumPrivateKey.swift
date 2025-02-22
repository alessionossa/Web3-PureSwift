//
//  EthereumPrivateKey.swift
//  Web3
//
//  Created by Koray Koska on 06.02.18.
//

import Foundation
import EllipticCurveKit
import CryptoSwift
import CryptoKit

public final class EthereumPrivateKey {

    // MARK: - Properties

    /// The raw private key bytes
    public let rawPrivateKey: Bytes

    /// The public key associated with this private key
    public let publicKey: EthereumPublicKey

    /// Returns the ethereum address representing the public key associated with this private key.
    public var address: EthereumAddress {
        return publicKey.address
    }

    // MARK: - Initialization

    /**
     * Initializes a new cryptographically secure `EthereumPrivateKey` from random noise.
     *
     * The process of generating the new private key is as follows:
     *
     * - Generate a secure random number between 55 and 65.590. Call it `rand`.
     * - Read `rand` bytes from `/dev/urandom` and call it `bytes`.
     * - Create the keccak256 hash of `bytes` and initialize this private key with the generated hash.
     */
    public convenience init() throws {
        guard var rand = Bytes.secureRandom(count: 2)?.bigEndianUInt else {
            throw Error.internalError
        }
        rand += 55

        guard let bytes = Bytes.secureRandom(count: Int(rand)) else {
            throw Error.internalError
        }
        let bytesHash = SHA3(variant: .keccak256).calculate(for: bytes)

        try self.init(privateKey: bytesHash)
    }

    /**
     * Convenient initializer for `init(privateKey:)`
     */
    public required convenience init(_ bytes: Bytes) throws {
        try self.init(privateKey: bytes)
    }

    /**
     * Initializes a new instance of `EthereumPrivateKey` with the given `privateKey` Bytes.
     *
     * `privateKey` must be exactly a big endian 32 Byte array representing the private key.
     *
     * The number must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
     *
     * So any number between
     *
     * 0x0000000000000000000000000000000000000000000000000000000000000001
     *
     * and
     *
     * 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
     *
     * is considered to be a valid secp256k1 private key.
     *
     * - parameter privateKey: The private key bytes.
     *
     * - throws: EthereumPrivateKey.Error.keyMalformed if the restrictions described above are not met.
     *           EthereumPrivateKey.Error.internalError if a secp256k1 library call or another internal call fails.
     *           EthereumPrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
     */
    public init(privateKey: Bytes) throws {
        guard privateKey.count == 32 else {
            throw Error.keyMalformed
        }
        self.rawPrivateKey = privateKey

        // *** Generate public key ***
        guard let ellipticPrivateKey = PrivateKey<Secp256k1>.init(base64: privateKey.asData) else {
            throw Error.keyMalformed
        }
        // secp256k1_ec_pubkey_create
        let publicKey = PublicKey<Secp256k1>(privateKey: ellipticPrivateKey)
        
        // secp256k1_ec_pubkey_serialize
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L428
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/secp256k1.c#L268
        //   (https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/src/secp256k1.c#L268)
        var pubOut = Bytes(data: publicKey.data.uncompressed)

        // First byte is header byte 0x04
        pubOut.remove(at: 0)

        self.publicKey = try EthereumPublicKey(publicKey: pubOut)
        // *** End Generate public key ***

        // Verify private key
        try verifyPrivateKey()
    }

    /**
     * Initializes a new instance of `EthereumPrivateKey` with the given `hexPrivateKey` hex string.
     *
     * `hexPrivateKey` must be either 64 characters long or 66 characters (with the hex prefix 0x).
     *
     * The number must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
     *
     * So any number between
     *
     * 0x0000000000000000000000000000000000000000000000000000000000000001
     *
     * and
     *
     * 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
     *
     * is considered to be a valid secp256k1 private key.
     *
     * - parameter hexPrivateKey: The private key bytes.
     *
     * - parameter ctx: An optional self managed context. If you have specific requirements and
     *                  your app performs not as fast as you want it to, you can manage the
     *                  `secp256k1_context` yourself with the public methods
     *                  `secp256k1_default_ctx_create` and `secp256k1_default_ctx_destroy`.
     *                  If you do this, we will not be able to free memory automatically and you
     *                  __have__ to destroy the context yourself once your app is closed or
     *                  you are sure it will not be used any longer. Only use this optional
     *                  context management if you know exactly what you are doing and you really
     *                  need it.
     *
     * - throws: EthereumPrivateKey.Error.keyMalformed if the restrictions described above are not met.
     *           EthereumPrivateKey.Error.internalError if a secp256k1 library call or another internal call fails.
     *           EthereumPrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
     */
    public convenience init(hexPrivateKey: String, ctx: OpaquePointer? = nil) throws {
        guard hexPrivateKey.count == 64 || hexPrivateKey.count == 66 else {
            throw Error.keyMalformed
        }

        var hexPrivateKey = hexPrivateKey

        if hexPrivateKey.count == 66 {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 0)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 2)
            let prefix = String(hexPrivateKey[s..<e])

            guard prefix == "0x" else {
                throw Error.keyMalformed
            }

            // Remove prefix
            hexPrivateKey = String(hexPrivateKey[e...])
        }

        var raw = Bytes()
        for i in stride(from: 0, to: hexPrivateKey.count, by: 2) {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i + 2)

            guard let b = Byte(String(hexPrivateKey[s..<e]), radix: 16) else {
                throw Error.keyMalformed
            }
            raw.append(b)
        }

        try self.init(privateKey: raw)
    }

    // MARK: - Convenient functions

    public func sign(message: Bytes) throws -> (v: UInt, r: Bytes, s: Bytes) {
        let hash = SHA3(variant: .keccak256).calculate(for: message)
        return try sign(hash: hash)
    }

    public func sign(hash _hash: Array<UInt8>) throws -> (v: UInt, r: Bytes, s: Bytes) {
        let hash = _hash
        guard hash.count == 32 else {
            throw Error.internalError
        }
                
        guard let seckey = PrivateKey<Secp256k1>(number: rawPrivateKey.asNumber) else {
            throw Error.internalError
        }
        let ellipticPublicKey = PublicKey<Secp256k1>(privateKey: seckey)
        
        // secp256k1_ecdsa_sign_recoverable
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/include/secp256k1_recovery.h#L84
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/src/modules/recovery/main_impl.h#L123
        // Call to `secp256k1_ecdsa_sign_inner` https://github.com/bitcoin-core/secp256k1/blob/master/src/secp256k1.c#L510
        let (signature, recid) = ECDSA<Secp256k1>.sign(Message(rawData: hash.asData), privateKey: seckey, publicKey: ellipticPublicKey, hashFunction: SHA256())
        
        // .sign(Message(rawData: hash.asData), using: .init(private: ellipticPrivateKey, public: ellipticPublicKey))
        
        // secp256k1_ecdsa_recoverable_signature_serialize_compact
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/include/secp256k1_recovery.h#L64
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/src/modules/recovery/main_impl.h#L60

        guard recid == 0 || recid == 1 else {
            // Well I guess this one should never happen but to avoid bigger problems...
            throw Error.internalError
        }
        guard Bytes(data: signature.r.as256bitLongData()).count == 32 && Bytes(data: signature.s.as256bitLongData()).count == 32 else {
            fatalError("Incorrect")
        }
        return (v: UInt(recid), r: Bytes(data: signature.r.as256bitLongData()), s: Bytes(data: signature.s.as256bitLongData()))
    }

    /**
     * Returns this private key serialized as a hex string.
     */
    public func hex() -> String {
        var h = "0x"
        for b in rawPrivateKey {
            h += String(format: "%02x", b)
        }

        return h
    }

    // MARK: - Helper functions

    private func verifyPrivateKey() throws {
        let secret = rawPrivateKey
        // secp256k1_ec_seckey_verify
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/include/secp256k1.h#L670
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/secp256k1.c#L580
        guard PrivateKey<Secp256k1>(number: secret.asNumber) != nil else {
            throw Error.keyMalformed
        }
    }

    // MARK: - Errors

    public enum Error: Swift.Error {

        case internalError
        case keyMalformed
        case pubKeyGenerationFailed
    }

    // MARK: - Deinitialization

    deinit { }
}

// MARK: - Equatable

extension EthereumPrivateKey: Equatable {

    public static func ==(_ lhs: EthereumPrivateKey, _ rhs: EthereumPrivateKey) -> Bool {
        return lhs.rawPrivateKey == rhs.rawPrivateKey
    }
}

// MARK: - BytesConvertible

extension EthereumPrivateKey: BytesConvertible {

    public func makeBytes() -> Bytes {
        return rawPrivateKey
    }
}

// MARK: - Hashable

extension EthereumPrivateKey: Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawPrivateKey)
    }
}

