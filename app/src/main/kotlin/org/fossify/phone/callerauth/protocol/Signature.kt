package org.fossify.phone.callerauth.protocol

import org.fossify.phone.callerauth.protocol.Signing
import org.json.JSONObject
import java.security.PublicKey

data class RsSignature(val signature: ByteArray, val publicKey: PublicKey) {
    fun verify(message: ByteArray): Boolean {
        return Signing.regSigVerify(publicKey, signature, message)
    }

    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pk", Signing.encodeToHex(publicKey.encoded))
            put("sg", Signing.encodeToHex(signature))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): RsSignature {
            val pkBytes = Signing.decodeHex(data.getString("pk"))
            return RsSignature(
                Signing.decodeHex(data.getString("sg")),
                Signing.decodePublicKey(pkBytes)
            )
        }
    }
}
