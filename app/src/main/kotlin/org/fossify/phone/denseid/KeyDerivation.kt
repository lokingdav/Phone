package org.fossify.phone.denseid

import android.util.Log
import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import denseid.keyderivation.v1.KeyDerivationServiceGrpc
import denseid.keyderivation.v1.Keyderivation
import io.grpc.StatusRuntimeException
import org.fossify.phone.BuildConfig
import java.security.MessageDigest
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.concurrent.TimeUnit
import kotlin.experimental.xor

/**
 * Utility for performing one-round OPRF evaluations against a KeyDerivationService.
 */
object KeyDerivation {
    private const val TAG = "Dense Identity"
    private const val HASH_ALG = "SHA-256"

    fun run(recipient: String): SharedState {
        val sharedState = UserState.getSharedState(recipient)
        if (sharedState != null) {
            Log.d(TAG, "Shared state found for $recipient:\n${sharedState.toJson()}")
            return sharedState
        }

        // Blind input
        val src = UserState.display.phoneNumber
        val ts = LocalDate.now(ZoneOffset.UTC).toString()
        val descriptor = Utilities.hash("$src$recipient$ts")
        val (blindedPoint, scalar) = OPRF.blind(descriptor)

        // Build and sign request with group signatures
        var request = Keyderivation.EvaluateRequest.newBuilder()
            .setBlindedElement(ByteString.copyFrom(blindedPoint.encoded))
            .build()

        val sigma = UserState.groupKeys.sign(request.toByteArray())
        request = request.toBuilder()
            .setSigma(ByteString.copyFrom(sigma))
            .build()

        val kd1Res = callServer(
            BuildConfig.KD1_HOST,
            BuildConfig.KD1_PORT,
            request,
            "KD1"
        )

        val kd2Res = callServer(
            BuildConfig.KD2_HOST,
            BuildConfig.KD2_PORT,
            request,
            "KD2"
        )

        return finalize(recipient, scalar, kd1Res, kd2Res)
    }

    fun finalize(
        recipient: String,
        scalar: Scalar,
        kd1Res: Keyderivation.EvaluateResponse,
        kd2Res: Keyderivation.EvaluateResponse
    ): SharedState {
        val y1 = OPRF.finalize(
            Point(kd1Res.evaluatedElement.toByteArray()),
            scalar
        )
        val y2 = OPRF.finalize(
            Point(kd2Res.evaluatedElement.toByteArray()),
            scalar
        )
        val sharedKey = hashXor(y1.encoded, y2.encoded)
        val state = UserState.addSharedState(recipient, sharedKey)
        Log.d(TAG, "Shared State: ${state.toJson()}")
        return state
    }

    fun hashXor(y1: ByteArray, y2: ByteArray): ByteArray {
        require(y1.size == y2.size) { "Inputs must have the same length" }
        val md = MessageDigest.getInstance(HASH_ALG)
        for (i in y1.indices) {
            md.update((y1[i] xor y2[i]))
        }
        return md.digest()
    }

    private fun callServer(
        host: String,
        port: Int,
        req: Keyderivation.EvaluateRequest,
        label: String
    ): Keyderivation.EvaluateResponse {
        Log.d(TAG, "↪ callServer($label) → $host:$port")

        val channel = ManagedChannelBuilder
            .forAddress(host, port)
            .usePlaintext()
            .build()

        val stub = KeyDerivationServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ [$label] sending RPC")
            val resp = stub.evaluate(req)
            val point = Signing.encodeToHex(resp.evaluatedElement.toByteArray())
            Log.d(TAG, "✔️ [$label] got Point=${point}")
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
