package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.Timestamp
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPair

private const val TAG = "CallAuth-UserState"

enum class KeyLabel(val code: String) {
    DID("DId"),
    DISPLAY_INFO("DN"),
    EID("EID"),
    EXP("EXP"),
    AMF_KP("AMF-KP"),
    ENR_KP("ENR-KP"),
    SIG("SIG"),

    TICKET("TKT"),
    SHARED_STATE("ST")
}

data class SharedState(
    val phoneNumber: String,
    var topic: String,
    var pk: AMFPublicKey,
    var secret: ByteArray,
) {
    fun persist() {
        Storage.putString(
            "${KeyLabel.SHARED_STATE.code}.${phoneNumber}",
            toJson().toString()
        )
    }

    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pn", phoneNumber)
            put("tpc", topic)
            put("pk", pk.toString())
            put("k", Signing.encodeToHex(secret))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): SharedState {
            return SharedState(
                data.getString("pn"),
                data.getString("tpc"),
                AMFPublicKey(Signing.decodeHex(data.getString("pk"))),
                Signing.decodeHex(data.getString("k"))
            )
        }
    }
}

object UserState {
    lateinit var eId: String
    lateinit var eExp: Timestamp
    lateinit var display: DisplayInfo
    lateinit var amfKp: AMFKeyPair
    lateinit var enrKp: MyKeyPair

    lateinit var signature: BbsSignature
    lateinit var tickets: Array<Ticket>

    fun update(
        eId: String,
        eExp: Timestamp,
        display: DisplayInfo,
        enrKp: MyKeyPair,
        amfKp: AMFKeyPair,
        signature: BbsSignature,
        tickets: Array<Ticket>
    ) {
        this.eId = eId
        this.eExp = eExp
        this.display = display
        this.enrKp = enrKp
        this.amfKp = amfKp
        this.signature = signature
        this.tickets = tickets
    }

    fun addSharedState(recipient: String, topic: String, pk: AMFPublicKey, secret: ByteArray): SharedState {
        val state = SharedState(recipient, topic, pk, secret)
        state.persist()
        return state
    }

    fun getSharedState(recipient: String): SharedState? {
        val dataStr = Storage.getString(
            "${KeyLabel.SHARED_STATE.code}.${recipient}"
        )
        if (dataStr.isNullOrBlank()) {
            return null
        }
        return SharedState.fromJson(JSONObject(dataStr))
    }

    fun persist() {
        val data = toJson().toString()
        Log.d(TAG, "Saving $data")
        Storage.putString(KeyLabel.DID.code, data)
    }

    fun toJson(): JSONObject {
        val state = JSONObject().apply {
            put(KeyLabel.DISPLAY_INFO.code, display.toJson())
            put(KeyLabel.EID.code, eId)
            put(KeyLabel.EXP.code, Signing.encodeToHex(eExp.toByteArray()))
            put(KeyLabel.AMF_KP.code, amfKp.toJson())
            put(KeyLabel.ENR_KP.code, enrKp.toJson())
            put(KeyLabel.SIG.code, signature.toJson())
            put(KeyLabel.TICKET.code, tickets.map { it.toJson() })
        }
        return state
    }

    fun load() {
        val dataStr = Storage.getString(KeyLabel.DID.code)
        if (dataStr.isNullOrBlank()) {
            return
        }

        val data = JSONObject(dataStr)

        try {
            val jsonArray = JSONArray(data.getString(KeyLabel.TICKET.code))
            val tickets = (0 until jsonArray.length()).map { i ->
                Ticket.fromJson(jsonArray.getJSONObject(i))
            }.toTypedArray()

            update(
                eId=data.getString(KeyLabel.EID.code),
                eExp=Timestamp.parseFrom(Signing.decodeHex(data.getString(KeyLabel.EXP.code))),
                display=DisplayInfo.fromJson(data.getJSONObject(KeyLabel.DISPLAY_INFO.code)),
                enrKp=MyKeyPair.fromJson(data.getJSONObject(KeyLabel.ENR_KP.code)),
                amfKp=AMFKeyPair.fromJson(data.getJSONObject(KeyLabel.AMF_KP.code)),
                signature=BbsSignature.fromJson(data.getJSONObject(KeyLabel.SIG.code)),
                tickets=tickets
            )
        } catch (e: Exception) {
            Log.e(TAG,"Failed to Load $TAG state", e)
        }
    }

    fun popTicket(): ByteArray {
        return "dummy".toByteArray()
    }
}
