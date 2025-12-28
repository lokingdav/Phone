package org.fossify.phone.callerauth.protocol

import org.fossify.phone.callerauth.UserState

/**
 * Configuration for a subscriber, containing all credentials needed for protocol operations.
 * This wraps UserState data in a protocol-friendly format.
 */
data class SubscriberConfig(
    val myPhone: String,
    val myName: String,
    val amfPublicKey: ByteArray,
    val amfPrivateKey: ByteArray,
    val pkePublicKey: ByteArray,
    val pkePrivateKey: ByteArray,
    val drPublicKey: ByteArray,
    val drPrivateKey: ByteArray,
    val enExpiration: ByteArray,
    val raPublicKey: ByteArray,
    val raSignature: ByteArray,
    val moderatorPublicKey: ByteArray,
    val sampleTicket: ByteArray
) {
    companion object {
        /**
         * Creates a SubscriberConfig from the current UserState.
         */
        fun fromUserState(): SubscriberConfig {
            return SubscriberConfig(
                myPhone = UserState.display.phoneNumber,
                myName = UserState.display.name,
                amfPublicKey = UserState.amfKp.public,
                amfPrivateKey = UserState.amfKp.private,
                pkePublicKey = UserState.pkeKp.public,
                pkePrivateKey = UserState.pkeKp.private,
                drPublicKey = UserState.drKp.public,
                drPrivateKey = UserState.drKp.private,
                enExpiration = UserState.eExp.toByteArray(),
                raPublicKey = UserState.signature.publicKey.encoded,
                raSignature = UserState.signature.signature,
                moderatorPublicKey = UserState.moderatorPublicKey,
                sampleTicket = UserState.popTicket()
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SubscriberConfig) return false
        return myPhone == other.myPhone
    }

    override fun hashCode(): Int = myPhone.hashCode()
}
