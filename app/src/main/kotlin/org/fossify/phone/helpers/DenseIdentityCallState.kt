package org.fossify.phone.helpers

import android.util.Log
import com.google.protobuf.Timestamp
import org.json.JSONObject

enum class KeyLabel(val code: String) {
    DID("DId"),
    PHONE_NUMBER("PN"),
    DISPLAY_NAME("DN"),
    LOGO_URL("LUrl"),
    N_BIO("nB"),
    PUBLIC_KEY("PK"),
    PRIVATE_KEY("SK"),
    EID("EID"),
    EXP("EXP"),
    SIG_1("SG1"),
    SIG_2("SG2"),
    USK("USK"),
    GPK("GPK"),
    NONCE("R");
}

data class DenseIdentityCallState(
    val phoneNumber: String,
    val displayName: String,
    var logoUrl: String,
    var nBio: Int,
    val nonce: String,

    val eId: String,
    val eExp: Timestamp,
    val ra1Sig: ByteArray,
    val ra2Sig: ByteArray,

    val publicKey: ByteArray,
    val privateKey: ByteArray,

    val userSk: ByteArray,
    val groupPk: ByteArray
) {
    fun getCommitmentAttributes(): List<String> {
        val attributes: List<String> = listOf(
            phoneNumber,
            displayName, logoUrl,
            nBio.toString(),
            nonce,
            Signing.encodeToHex(publicKey)
        )

        return attributes
    }

    fun save() {
        val enrollmentJson = JSONObject().apply {
            put(KeyLabel.PHONE_NUMBER.code,phoneNumber)
            put(KeyLabel.DISPLAY_NAME.code,displayName)
            put(KeyLabel.LOGO_URL.code,logoUrl)
            put(KeyLabel.N_BIO.code, nBio)

            put(KeyLabel.PUBLIC_KEY.code,Signing.encodeToHex(publicKey))
            put(KeyLabel.PRIVATE_KEY.code,Signing.encodeToHex(privateKey))

            put(KeyLabel.EID.code,eId)
            put(KeyLabel.EXP.code, Signing.encodeToHex(eExp.toByteArray()))
            put(KeyLabel.SIG_1.code,Signing.encodeToHex(ra1Sig))
            put(KeyLabel.SIG_2.code,Signing.encodeToHex(ra2Sig))

            put(KeyLabel.USK.code,Signing.encodeToHex(userSk))
            put(KeyLabel.GPK.code,Signing.encodeToHex(groupPk))
            put(KeyLabel.NONCE.code, nonce)
        }
        val data = enrollmentJson.toString()
        Log.d("DenseIdentityCallState", "Saving $data")
        DenseIdentityStore.putString(KeyLabel.DID.code, data)
    }

    companion object {
        fun load(): DenseIdentityCallState? {
            val dataStr = DenseIdentityStore.getString(KeyLabel.DID.code)
            if (dataStr.isNullOrBlank()) {
                return null
            }

            val data = JSONObject(dataStr)

            val phoneNumber = data.getString(KeyLabel.PHONE_NUMBER.code)
            val displayName = data.getString(KeyLabel.DISPLAY_NAME.code)
            val logoUrl = data.getString(KeyLabel.LOGO_URL.code)
            val nBio = data.getInt(KeyLabel.N_BIO.code)

            val pk = Signing.decodeHex(data.getString(KeyLabel.PUBLIC_KEY.code))
            val sk = Signing.decodeHex(data.getString(KeyLabel.PRIVATE_KEY.code))

            val eid = data.getString(KeyLabel.EID.code)
            val exp = Signing.decodeHex(data.getString(KeyLabel.EXP.code))
            val sig1 = Signing.decodeHex(data.getString(KeyLabel.SIG_1.code))
            val sig2 = Signing.decodeHex(data.getString(KeyLabel.SIG_2.code))

            val usk = Signing.decodeHex(data.getString(KeyLabel.USK.code))
            val gpk = Signing.decodeHex(data.getString(KeyLabel.GPK.code))
            val nonce = data.getString(KeyLabel.NONCE.code)

            return DenseIdentityCallState(
                phoneNumber,
                displayName,
                logoUrl,
                nBio,
                nonce,

                eid,
                Timestamp.parseFrom(exp),
                sig1,
                sig2,

                pk,
                sk,

                usk,
                gpk
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DenseIdentityCallState

        if (phoneNumber != other.phoneNumber) return false
        if (displayName != other.displayName) return false
        if (logoUrl != other.logoUrl) return false
        if (eId != other.eId) return false
        if (eExp != other.eExp) return false
        if (!ra1Sig.contentEquals(other.ra1Sig)) return false
        if (!ra2Sig.contentEquals(other.ra2Sig)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!privateKey.contentEquals(other.privateKey)) return false
        if (!userSk.contentEquals(other.userSk)) return false
        if (!groupPk.contentEquals(other.groupPk)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = phoneNumber.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + logoUrl.hashCode()
        result = 31 * result + eId.hashCode()
        result = 31 * result + eExp.hashCode()
        result = 31 * result + ra1Sig.contentHashCode()
        result = 31 * result + ra2Sig.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + privateKey.contentHashCode()
        result = 31 * result + userSk.contentHashCode()
        result = 31 * result + groupPk.contentHashCode()
        return result
    }
}
