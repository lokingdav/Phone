package org.fossify.phone.callerauth

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
