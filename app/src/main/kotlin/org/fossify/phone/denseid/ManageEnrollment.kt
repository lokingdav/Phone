package org.fossify.phone.denseid

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
            .addPublicKeys(ByteString.copyFrom(keypair.public.encoded))
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
            BuildConfig.ES1_HOST,
            BuildConfig.ES1_PORT,
            req, "ES1"
        )

        Log.d(TAG, "⚡ Calling ES2")
        val es2Res = callServer(
            BuildConfig.ES2_HOST,
            BuildConfig.ES2_PORT,
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
        Log.d(TAG, "Validating USK under GPK...")
        if (!groupKeys.verifyUsk()) {
            throw Exception("User Secret Key is Malformed")
        }
        Log.d(TAG, "\t✅ Valid")

        Log.d(TAG, "Constructing User State Object...")
        val display = DisplayInfo(phoneNumber, displayName, logoUrl)
        val miscInfo = MiscInfo(nBio, nonce)
        val ra1sig = RsSignature(
            es1.sigma.toByteArray(),
            Signing.decodePublicKey(es1.publicKey.toByteArray())
        )
        val ra2sig = RsSignature(
            es2.sigma.toByteArray(),
            Signing.decodePublicKey(es2.publicKey.toByteArray())
        )
        val enrollmentCred = Credential(es1.eid, es2.exp, ra1sig, ra2sig)
        val myKeyPair = MyKeyPair(keypair)

        UserState.update(
            display,
            miscInfo,
            enrollmentCred,
            myKeyPair,
            groupKeys
        )
        Log.d(TAG, "\t✅ Success!")

        Log.d(TAG, "Validating Enrollment ID...")
        if (es1.eid != es2.eid) {
            throw Exception("Eid from ES1 and ES2 are different")
        }
        val expectedEid = Signing.encodeToHex(Merkle.createRoot(UserState.getCommitmentAttributes()))
        if (UserState.enrollmentCred.eId != expectedEid) {
            throw Exception("Expected Eid does not match the computed value")
        }
        Log.d(TAG, "\t✅ Valid!")

        Log.d(TAG, "Validating Expiration Field...")
        if (es1.exp != es2.exp) {
            throw Exception("Expiration fields must match for both RA1 and RA2")
        }

        val enMsg = Enrollment.EnrollmentResponse.newBuilder()
            .setEid(expectedEid)
            .setExp(es1.exp) // since exp match, either es1.exp or es2.exp suffice
            .build()
            .toByteArray()

        Log.d(TAG, "Verifying Enrollment Credential from Registrar 1...")
        if (!UserState.enrollmentCred.ra1Sig.verify(enMsg)) {
            throw Exception("Enrollment signature failed to verify under Registrar 1")
        }
        Log.d(TAG, "\t✅ Valid!")

        Log.d(TAG, "Verifying Enrollment Credential from Registrar 2...")
        if (!UserState.enrollmentCred.ra2Sig.verify(enMsg)) {
            throw Exception("Enrollment signature failed to verify under Registrar 2")
        }
        Log.d(TAG, "\t✅ Valid!")

        Log.d(TAG, "Saving State...")
        UserState.persist()
        Log.d(TAG, "\t✅ Saved!")

        Log.d(TAG, "✅ Enrollment complete, eid=${UserState.enrollmentCred.eId}")
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
