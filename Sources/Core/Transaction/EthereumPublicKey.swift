//
//  EthereumPublicKey.swift
//  Web3
//
//  Created by Koray Koska on 07.02.18.
//

import Foundation
import EllipticCurveKit
import CryptoSwift
import BigInt
import CryptoKit

public final class EthereumPublicKey {

    // MARK: - Properties

    /// The raw public key bytes
    public let rawPublicKey: Bytes

    /// The `EthereumAddress` associated with this public key
    public let address: EthereumAddress

    // MARK: - Initialization

    /**
     * Convenient initializer for `init(publicKey:)`
     */
    public required convenience init(_ bytes: Bytes) throws {
        try self.init(publicKey: bytes)
    }

    /**
     * Initializes a new instance of `EthereumPublicKey` with the given raw uncompressed public key Bytes.
     *
     * `publicKey` must be either a 64 Byte array (containing the uncompressed public key)
     * or a 65 byte array where the first byte must be the uncompressed header byte 0x04
     * and the following 64 bytes must be the uncompressed public key.
     *
     * - parameter publicKey: The uncompressed public key either with the header byte 0x04 or without.
     *
     * - throws: EthereumPublicKey.Error.keyMalformed if the given `publicKey` does not fulfill the requirements from above.
     *           EthereumPublicKey.Error.internalError if a secp256k1 library call or another internal call fails.
     */
    public init(publicKey: Bytes) throws {
        guard publicKey.count == 64 || publicKey.count == 65 else {
            throw Error.keyMalformed
        }
        var publicKey = publicKey
        if publicKey.count == 65 {
            guard publicKey[0] == 0x04 else {
                throw Error.keyMalformed
            }
            publicKey.remove(at: 0)
        }
        self.rawPublicKey = publicKey

        // Generate associated ethereum address
        var hash = SHA3(variant: .keccak256).calculate(for: publicKey)
        guard hash.count == 32 else {
            throw Error.internalError
        }
        hash = Array(hash[12...])
        self.address = try EthereumAddress(rawAddress: hash)

        // Verify public key
        try verifyPublicKey()
    }

    /**
     * Initializes a new instance of `EthereumPublicKey` with the message and corresponding signature.
     * This is done by extracting the public key from the recoverable signature, which guarantees a
     * valid signature.
     *
     * - parameter message: The original message which will be used to generate the hash which must match the given signature.
     * - paramater v: The recovery id of the signature. Must be 0, 1, 2 or 3 or Error.signatureMalformed will be thrown.
     * - parameter r: The r value of the signature.
     * - parameter s: The s value of the signature.
     *
     * - throws: EthereumPublicKey.Error.signatureMalformed if the signature is not valid or in other ways malformed.
     *           EthereumPublicKey.Error.internalError if a secp256k1 library call or another internal call fails.
     */
    public init(message: Bytes, v: EthereumQuantity, r: EthereumQuantity, s: EthereumQuantity) throws {
        let originalR = r
        let originalS = s

        // Create raw signature array
        var rawSig = Bytes()
        var r = r.quantity.makeBytes().trimLeadingZeros()
        var s = s.quantity.makeBytes().trimLeadingZeros()

        guard r.count <= 32 && s.count <= 32 else {
            throw Error.signatureMalformed
        }
        guard let vUInt = v.quantity.makeBytes().bigEndianUInt, vUInt <= Int32.max else {
            throw Error.signatureMalformed
        }
        let v = Int32(vUInt)

        for _ in 0..<(32 - r.count) {
            r.insert(0, at: 0)
        }
        for _ in 0..<(32 - s.count) {
            s.insert(0, at: 0)
        }

        rawSig.append(contentsOf: r)
        rawSig.append(contentsOf: s)

        // Parse recoverable signature
        // secp256k1_ecdsa_recoverable_signature_parse_compact
        // secp256k1_ecdsa_recoverable_signature_parse_compact(finalCtx, recsig, &rawSig, v)
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_recovery.h#L36
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h#L38
        guard let signature = EllipticCurveKit.Signature<Secp256k1>(r: Number(originalR.quantity), s: Number(originalS.quantity), ensureLowSAccordingToBIP62: true) else {
            throw Error.signatureMalformed
        }
        /*
        guard let recoverableSignature = ECDSA<Secp256k1>.Signature(r: Number(originalR.quantity), s: Number(originalS.quantity), recoveryId: Int(v)) else {
            throw Error.signatureMalformed
        }
         */

        // Recover public key
        let hash = SHA3(variant: .keccak256).calculate(for: message)
        guard hash.count == 32 else {
            throw Error.internalError
        }
        // secp256k1_ecdsa_recover
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_recovery.h#L102
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h#L137
        // Call to `secp256k1_ecdsa_sig_recover` https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h#L87`
            // Call to `secp256k1_gej_set_ge` https://github.com/bitcoin-core/secp256k1/blob/master/src/group_impl.h#L329
                    // Call to `secp256k1_fe_set_int` https://github.com/bitcoin-core/secp256k1/blob/master/src/field_impl.h#L217
        guard let recoveredPublicKey = ECDSA<Secp256k1>.recoverPublicKey(message: Message(rawData: hash.asData), signature: signature, recoveryParam: Int(v)) else {
            throw Error.signatureMalformed
        }

        // Generate uncompressed public key bytes
        // secp256k1_ec_pubkey_serialize
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L428
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/secp256k1.c#L268
        var rawPubKey = Bytes(data: recoveredPublicKey.data.uncompressed)

        rawPubKey.remove(at: 0)
        self.rawPublicKey = rawPubKey

        // Generate associated ethereum address
        var pubHash = SHA3(variant: .keccak256).calculate(for: rawPubKey)
        guard pubHash.count == 32 else {
            throw Error.internalError
        }
        pubHash = Array(pubHash[12...])
        self.address = try EthereumAddress(rawAddress: pubHash)

        // Final check for signature validity

        let signatureVerified = try verifySignature(message: message, v: vUInt, r: originalR.quantity, s: originalS.quantity)
        if !signatureVerified {
            throw Error.signatureMalformed
        }
    }

    /**
     * Initializes a new instance of `EthereumPublicKey` with the given uncompressed hex string.
     *
     * `hexPublicKey` must have either 128 characters (containing the uncompressed public key)
     * or 130 characters in which case the first two characters must be the hex prefix 0x
     * and the following 128 characters must be the uncompressed public key.
     *
     * - parameter hexPublicKey: The uncompressed hex public key either with the hex prefix 0x or without.
     *
     * - throws: EthereumPublicKey.Error.keyMalformed if the given `hexPublicKey` does not fulfill the requirements from above.
     *           EthereumPublicKey.Error.internalError if a secp256k1 library call or another internal call fails.
     */
    public convenience init(hexPublicKey: String) throws {
        guard hexPublicKey.count == 128 || hexPublicKey.count == 130 else {
            throw Error.keyMalformed
        }

        try self.init(publicKey: hexPublicKey.hexBytes())
    }

    // MARK: - Convenient functions

    public func verifySignature(message: Bytes, v: UInt, r: BigUInt, s: BigUInt) throws -> Bool {
        // Get public key
        var rawpubKey = rawPublicKey
        rawpubKey.insert(0x04, at: 0)
        // secp256k1_ec_pubkey_parse
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L406
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/secp256k1.c#L250
        // Call to `secp256k1_eckey_pubkey_parse` https://github.com/bitcoin-core/secp256k1/blob/master/src/eckey_impl.h#L17
        let affinePoint = try AffinePoint<Secp256k1>.decodeFromUncompressedPublicKey(bytes: rawpubKey.asData)
        let publicKey = PublicKey<Secp256k1>(point: affinePoint)

        // Create raw signature array
        var rawSig = Bytes()
        var rBytes = r.makeBytes().trimLeadingZeros()
        var sBytes = s.makeBytes().trimLeadingZeros()

        guard rBytes.count <= 32 && sBytes.count <= 32 else {
            throw Error.signatureMalformed
        }
        guard v <= Int32.max else {
            throw Error.signatureMalformed
        }

        for _ in 0..<(32 - rBytes.count) {
            rBytes.insert(0, at: 0)
        }
        for _ in 0..<(32 - sBytes.count) {
            sBytes.insert(0, at: 0)
        }

        rawSig.append(contentsOf: rBytes)
        rawSig.append(contentsOf: sBytes)

        // Parse recoverable signature
        // secp256k1_ecdsa_recoverable_signature_parse_compact
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_recovery.h#L36
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h#L38
        
        // Convert to normal signature
        // secp256k1_ecdsa_recoverable_signature_convert
        // Declaration: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_recovery.h#L50
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/recovery/main_impl.h#L74
        
        guard let signature = EllipticCurveKit.Signature<Secp256k1>.init(r: Number(r), s: Number(s), ensureLowSAccordingToBIP62: true) else {
            throw Error.signatureMalformed
        }

        // Check validity with signature
        let hash = SHA3(variant: .keccak256).calculate(for: message)
        guard hash.count == 32 else {
            throw Error.internalError
        }
        
        // secp256k1_ecdsa_verify
        // secp256k1_ecdsa_verify(ctx, sig, &hash, pubkey) == 1
        // Implementation: https://github.com/bitcoin-core/secp256k1/blob/2e3bf136532e48a88baec544d485e54f7bd29db8/src/secp256k1.c#L450
        return ECDSA<Secp256k1>.verify(.init(rawData: hash.asData), wasSignedBy: signature, publicKey: publicKey)
    }

    /**
     * Returns this public key serialized as a hex string.
     */
    public func hex() -> String {
        var h = "0x"
        for b in rawPublicKey {
            h += String(format: "%02x", b)
        }

        return h
    }

    // MARK: - Helper functions

    private func verifyPublicKey() throws {
        var pubKey = rawPublicKey
        pubKey.insert(0x04, at: 0)
        
        guard ((try? AffinePoint<Secp256k1>.decodeFromUncompressedPublicKey(bytes: pubKey.asData)) != nil) else {
            throw Error.keyMalformed
        }
    }

    // MARK: - Errors

    public enum Error: Swift.Error {

        case internalError
        case keyMalformed
        case signatureMalformed
    }

    // MARK: - Deinitialization

    deinit { }
}

// MARK: - Equatable

extension EthereumPublicKey: Equatable {

    public static func ==(_ lhs: EthereumPublicKey, _ rhs: EthereumPublicKey) -> Bool {
        return lhs.rawPublicKey == rhs.rawPublicKey
    }
}

// MARK: - BytesConvertible

extension EthereumPublicKey: BytesConvertible {

    public func makeBytes() -> Bytes {
        return rawPublicKey
    }
}

// MARK: - Hashable

extension EthereumPublicKey: Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawPublicKey)
    }
}
