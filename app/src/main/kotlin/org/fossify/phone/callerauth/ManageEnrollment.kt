package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.github.lokingdav.libdia.LibDia
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import java.security.KeyPair
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.math.log

/**
 * Handles key generation, request marshaling, signing over the serialized proto,
 * sequential gRPC calls, result gathering and consolidated logging.
 */
object ManageEnrollment {
    private const val TAG = "CallAuth-ManageEnrollment"

    /**
     * Builds a signed EnrollmentRequest, performs two RPCs in sequence,
     * and logs all results together.
     */
    suspend fun enroll(
        phoneNumber: String,
        displayName: String,
        logoUrl: String
    ) = coroutineScope {
        Log.d(TAG, "▶ enroll() start for $phoneNumber")

        // Generate signing keypair
        val enrKp = MyKeyPair(Signing.regSigKeygen())
        val amfKp = AMF.keygen()
        val blindedTickets = VOPRF.generateTicket(1)

        // Build the DisplayInformation message
        val iden = Enrollment.DisplayInformation.newBuilder()
            .setName(displayName)
            .setLogoUrl(logoUrl)
            .build()

        // Build the unsigned EnrollmentRequest
        val nonce = UUID.randomUUID().toString()
        val unsigned = Enrollment.EnrollmentRequest.newBuilder()
            .setTn(phoneNumber)
            .setPk(ByteString.copyFrom(amfKp.public))
            .setIpk(ByteString.copyFrom(enrKp.public.encoded))
            .setIden(iden)
            .setNonce(nonce)
            .addAllBlindedTickets(blindedTickets.map {
                ByteString.copyFrom(it.blinded.encoded)
            })
            .build()

        // Sign the exact protobuf bytes
        val toSign = unsigned.toByteArray()
        val signatureBytes = Signing.regSigSign(enrKp.private, toSign)
        val signatureHex = Signing.encodeToHex(signatureBytes)
        Log.d(TAG, "✍️ Signed proto bytes, signature=$signatureHex")

        // Build the final signed request
        val req = unsigned.toBuilder()
            .setSigma(ByteString.copyFrom(signatureBytes))
            .build()
        Log.d(TAG, "📨 Built signed EnrollmentRequest")


        Log.d(TAG, "⚡ Calling Enrollment Server")
        val eRes = callServer(req)

        // Finalize
        try {
            finalizeEnrollment(
                phoneNumber,
                displayName,
                logoUrl,
                enrKp,
                amfKp,
                eRes,
                blindedTickets,
                req.nonce
            )
            Log.d(TAG, "Enrollment Complete. Happy Calling")
        } catch (e: Exception) {
            val msg = "❌ Enrollment failed: ${e.message}"
            Log.e(TAG, msg, e)
        }
    }

    private fun finalizeEnrollment(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        enrKp: MyKeyPair,
        amfKp: AMFKeyPair,
        eRes: Enrollment.EnrollmentResponse,
        blindedTickets: Array<BlindedTicket>,
        nonce: String
    ) {
        Log.d(TAG, "Constructing User State Object...")
        val display = DisplayInfo(phoneNumber, displayName, logoUrl)
        val signature = BbsSignature(
            eRes.sigma.toByteArray(),
            BbsPublicKey(eRes.epk.toByteArray())
        )
        val tickets = VOPRF.finalizeTickets(blindedTickets, eRes.evaluatedTicketsList.map {
            Point(it.toByteArray())
        }.toTypedArray())

        UserState.update(
            eId=eRes.eid,
            eExp=eRes.exp,
            display=display,
            enrKp=enrKp,
            amfKp=amfKp,
            signature=signature,
            tickets=tickets
        )
        Log.d(TAG, "\t✅ Success!")

        Log.d(TAG, "Verifying Tickets...")
        if (!VOPRF.verifyTickets(tickets, eRes.avk.toByteArray())) {
            throw Exception("tickets failed to verify")
        }
        Log.d(TAG, "\t✅ Valid!")

        Log.d(TAG, "Verifying Enrollment Credential...")
        // create attributes as array of strings
        val attributes = arrayOf(
            eRes.eid,
            Signing.encodeToHex(eRes.exp.toByteArray()),
            displayName,
            logoUrl,
            Signing.encodeToHex(amfKp.public),
            Signing.encodeToHex(enrKp.public.encoded),
            nonce
        )
        // append phoneNumber to every val in attributes
        attributes.forEachIndexed { i, v -> attributes[i] = "$v$phoneNumber" }

        Log.d(TAG, "\tAttributes: \n\t\t${attributes.joinToString("\n\t\t")}")

        if (!signature.verify(attributes)) {
            throw Exception("Enrollment signature failed to verify under Registrar 1")
        }
        Log.d(TAG, "\t✅ Valid!")

        Log.d(TAG, "Saving State...")
        UserState.persist()
        Log.d(TAG, "\t✅ Saved!")

        Log.d(TAG, "✅ Enrollment complete, eid=${UserState.eId}")
    }

    private fun callServer(req: Enrollment.EnrollmentRequest): Enrollment.EnrollmentResponse {
        val channel = ManagedChannelBuilder
            .forAddress(BuildConfig.ES_HOST, BuildConfig.ES_PORT)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending RPC")
            val resp = stub.enrollSubscriber(req)
            Log.d(TAG, "✔️ Got eid=${resp.eid}")
            return resp
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ RPC failed: ${e.status}", e)
            throw e
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ Channel shutdown")
        }
    }
}
