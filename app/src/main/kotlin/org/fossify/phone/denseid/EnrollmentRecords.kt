package org.fossify.phone.denseid

import android.util.Log
import com.google.protobuf.Timestamp
import org.json.JSONObject

data class DisplayInfo(
    val phoneNumber: String,
    val name: String,
    val logoUrl: String
) {
    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pn", phoneNumber)
            put("nm", name)
            put("lg", logoUrl)
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): DisplayInfo {
            return DisplayInfo(
                data.getString("pn"),
                data.getString("nm"),
                data.getString("lg")
            )
        }
    }
}

data class MiscInfo(val nBio: Int, val nonce: String) {
    fun toJson(): JSONObject {
        val misc = JSONObject().apply {
            put("nb", nBio)
            put("nc", nonce)
        }
        return misc
    }
    companion object {
        fun fromJson(data: JSONObject): MiscInfo {
            return MiscInfo(data.getInt("nb"), data.getString("nc"))
        }
    }
}

data class Credential(
    val eId: String,
    val eExp: Timestamp,
    val ra1Sig: RsSignature,
    val ra2Sig: RsSignature
) {
    fun toJson(): JSONObject {
        val exp = Signing.encodeToHex(eExp.toByteArray())

        val data = JSONObject().apply {
            put("ei", eId)
            put("ex", exp)
            put("r1", ra1Sig.toJson())
            put("r2", ra2Sig.toJson())
        }

        return data
    }

    companion object {
        fun fromJson(data: JSONObject): Credential {
            val exp = Signing.decodeHex(data.getString("ex"))
            return Credential(
                data.getString("ei"),
                Timestamp.parseFrom(exp),
                RsSignature.fromJson(data.getJSONObject("r1")),
                RsSignature.fromJson(data.getJSONObject("r2")),
            )
        }
    }
}
