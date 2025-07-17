package org.fossify.phone.helpers.denseid

import java.security.PublicKey

private const val delimiter = "."

class Signature {
    var signature: ByteArray
    var publicKey: PublicKey

    constructor(signature: ByteArray, publicKey: PublicKey) {
        this.signature = signature
        this.publicKey = publicKey
    }

    constructor(signature: ByteArray, publicKey: ByteArray) {
        this.signature = signature
        this.publicKey = Signing.decodePublicKey(publicKey)
    }

    constructor(str: String) {
        val parts = str.split(delimiter)
        val pkHex = parts[0]
        val sigHex = parts[1]
        this.publicKey = Signing.decodePublicKey(Signing.decodeHex(pkHex))
        this.signature = Signing.decodeHex(sigHex)
    }

    fun verify(message: ByteArray): Boolean {
        return Signing.regSigVerify(publicKey, signature, message)
    }

    override fun toString(): String {
        val pkHex: String = Signing.encodeToHex(publicKey.encoded)
        val sigHex: String = Signing.encodeToHex(signature)
        return "$pkHex.$sigHex"
    }
}
