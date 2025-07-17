package org.fossify.phone.helpers.denseid

import android.util.Log
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import java.security.KeyPair
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Handles key generation, request marshaling, signing over the serialized proto,
 * sequential gRPC calls, result gathering and consolidated logging.
 */
object ManageEnrollment {
    private const val TAG = "DenseID-ManageEnrollment"
    private const val PREFIX: String = "denseid"

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

        // 1) Generate signing keypair
        val keypair = Signing.regSigKeygen()

        // 2) Build the DisplayInformation message
        val iden = Enrollment.DisplayInformation.newBuilder()
            .setName(displayName)
            .setLogoUrl(logoUrl)
            .build()

        // 3) Build the unsigned EnrollmentRequest
        val nonce = UUID.randomUUID().toString()
        val unsigned = Enrollment.EnrollmentRequest.newBuilder()
            .setTn(phoneNumber)
            .addPublicKeys(ByteString.copyFrom(Signing.toRawPublicKey(keypair.public)))
            .setIden(iden)
            .setNBio(0)
            .addAllAuthSigs(emptyList())
            .setNonce(nonce)
            .build()

        // 4) Sign the exact protobuf bytes
        val toSign = unsigned.toByteArray()
        val signatureBytes = Signing.regSigSign(keypair.private, toSign)
        val signatureHex = Signing.encodeToHex(signatureBytes)
        Log.d(TAG, "✍️ Signed proto bytes, signature=$signatureHex")

        // 5) Build the final signed request
        val req = unsigned.toBuilder()
            .addAuthSigs(ByteString.copyFrom(signatureBytes))
            .build()
        Log.d(TAG, "📨 Built signed EnrollmentRequest")

        // 6) Sequential calls
        Log.d(TAG, "⚡ Calling ES1")
        val es1Res = callServer(
            BuildConfig.DENSEID_ES1_HOST,
            BuildConfig.DENSEID_ES1_PORT,
            req, "ES1"
        )

        Log.d(TAG, "⚡ Calling ES2")
        val es2Res = callServer(
            BuildConfig.DENSEID_ES2_HOST,
            BuildConfig.DENSEID_ES2_PORT,
            req, "ES2"
        )

        // 7) Finalize
        try {
            finalizeEnrollment(
                phoneNumber,
                displayName,
                logoUrl,
                nonce,
                0,
                es1Res,
                es2Res,
                keypair
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
        nonce: String,
        nBio: Int,
        es1: Enrollment.EnrollmentResponse,
        es2: Enrollment.EnrollmentResponse,
        keypair: KeyPair
    ) {
        val groupKeys = GroupKeys(
            USK(es1.usk.toByteArray()),
            GPK(es1.gpk.toByteArray())
        )

        if (!groupKeys.verifyUsk()) {
            throw Exception("User Secret Key is Malformed")
        }

        val display = DisplayInfo(phoneNumber, displayName, logoUrl)
        val miscInfo = MiscInfo(nBio, nonce)
        val ra1sig = Signature(
            es1.sigma.toByteArray(),
            Signing.fromRawPublicKey(es1.publicKey.toByteArray())
        )
        val ra2sig = Signature(
            es2.sigma.toByteArray(),
            Signing.fromRawPublicKey(es2.publicKey.toByteArray())
        )
        val enrollmentCred = Credential(es1.eid, es2.exp, ra1sig, ra2sig)
        val myKeyPair = MyKeyPair(keypair)


        val state = UserState(
            display,
            miscInfo,
            enrollmentCred,
            myKeyPair,
            groupKeys
        )



        val expectedEid = Signing.encodeToHex(Merkle.createRoot(state.getCommitmentAttributes()))
        if (state.eId != expectedEid) {
            throw Exception("Eid Check fails")
        }

        val enMsg = Enrollment.EnrollmentResponse.newBuilder()
            .setEid(expectedEid)
            .setExp(es1.exp)
            .build()
            .toByteArray()

        if (!Signing.regSigVerify(
                es1.publicKey.toByteArray(),
                enMsg,
                es1.sigma.toByteArray())) {
            throw Exception("Enrollment signature failed to verify under Registrar 1")
        }

        if (!Signing.regSigVerify(
                es2.publicKey.toByteArray(),
                enMsg,
                es2.sigma.toByteArray())) {
            throw Exception("Enrollment signature failed to verify under Registrar 2")
        }

        state.save()

        Log.d(TAG, "✅ Enrollment complete, eid=${state.eId}")
    }

    private fun callServer(
        host: String,
        port: Int,
        req: Enrollment.EnrollmentRequest,
        label: String
    ): Enrollment.EnrollmentResponse {
        Log.d(TAG, "↪ callServer($label) → $host:$port")
        val channel = ManagedChannelBuilder
            .forAddress(host, port)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ [$label] sending RPC")
            val resp = stub.enrollSubscriber(req)
            Log.d(TAG, "✔️ [$label] got eid=${resp.eid}")
            return resp
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ [$label] RPC failed: ${e.status}", e)
            throw e
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ callServer($label) channel shutdown")
        }
    }
}
