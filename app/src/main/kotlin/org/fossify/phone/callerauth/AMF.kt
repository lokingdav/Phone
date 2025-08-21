package org.fossify.phone.callerauth

import io.github.lokingdav.libdia.LibDia
import org.json.JSONObject

data class AMFPublicKey(val encoded: ByteArray) {
    override fun toString(): String {
        return Signing.encodeToHex(encoded);
    }
}

data class AMFKeyPair(val private: ByteArray, val public: ByteArray) {
    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pk", Signing.encodeToHex(public))
            put("sk", Signing.encodeToHex(private))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): AMFKeyPair {
            return AMFKeyPair(
                Signing.decodeHex(data.getString("sk")),
                Signing.decodeHex(data.getString("pk"))
            )
        }
    }
}

object AMF {
    fun keygen(): AMFKeyPair {
        val (sk, pk) = LibDia.amfKeygen()
        return AMFKeyPair(sk, pk)
    }
}
