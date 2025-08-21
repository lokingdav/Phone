package org.fossify.phone.callerauth

import android.util.Log
import io.grpc.ManagedChannelBuilder
import com.google.protobuf.ByteString
import denseid.keyderivation.v1.KeyDerivationServiceGrpc
import denseid.keyderivation.v1.Keyderivation
import io.grpc.StatusRuntimeException
import org.fossify.phone.BuildConfig
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.concurrent.TimeUnit

/**
 * Utility for performing one-round OPRF evaluations against a KeyDerivationService.
 */
object KeyDerivation {
    private const val TAG = "CallAuth-KeyDerivation"

    fun run(callerId: String): ByteArray {
        val ts = LocalDate.now(ZoneOffset.UTC).toString()
        val descriptor = Utilities.hash("$callerId$ts")
        val (blindedPoint, scalar) = VOPRF.blind(descriptor)

        val request = Keyderivation.EvaluateRequest.newBuilder()
            .setBlindedElement(ByteString.copyFrom(blindedPoint.encoded))
            .setTicket(ByteString.copyFrom(UserState.popTicket()))
            .build()

        val res = callServer(request)

        val evaluated = Point(res.evaluatedElement.toByteArray())

        return VOPRF.finalize(evaluated, scalar).encoded
    }

    private fun callServer(req: Keyderivation.EvaluateRequest): Keyderivation.EvaluateResponse {
        val channel = ManagedChannelBuilder
            .forAddress(BuildConfig.KS_HOST, BuildConfig.KS_PORT)
            .usePlaintext()
            .build()

        val stub = KeyDerivationServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending RPC")
            val resp = stub.evaluate(req)
            val point = Signing.encodeToHex(resp.evaluatedElement.toByteArray())
            Log.d(TAG, "✔️ Got Point=${point}")
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
