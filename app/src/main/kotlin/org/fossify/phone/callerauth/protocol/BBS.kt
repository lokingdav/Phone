package org.fossify.phone.callerauth.protocol

import io.github.lokingdav.libdia.LibDia
import org.fossify.phone.callerauth.protocol.Signing
import org.json.JSONObject

data class  BbsPublicKey(val encoded: ByteArray)
data class BbsSignature(val signature: ByteArray, val publicKey: BbsPublicKey) {
    fun verify(messages: Array<String>): Boolean {
        val msgs = messages.map { it.toByteArray() }.toTypedArray()
        return LibDia.bbsVerify(msgs, publicKey.encoded, signature)
    }

    fun verify(messages: Array<ByteArray>): Boolean {
        return LibDia.bbsVerify(messages, publicKey.encoded, signature)
    }

    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("sig", Signing.encodeToHex(signature))
            put("pk", Signing.encodeToHex(publicKey.encoded))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): BbsSignature {
            return BbsSignature(
                Signing.decodeHex(data.getString("sig")),
                BbsPublicKey(Signing.decodeHex(data.getString("pk")))
            )
        }
    }
}


object BBS {

}
