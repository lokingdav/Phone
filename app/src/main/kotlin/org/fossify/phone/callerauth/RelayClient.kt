package org.fossify.phone.callerauth

import io.grpc.ManagedChannel
import io.grpc.Status
import io.grpc.okhttp.OkHttpChannelBuilder
import denseid.relay.v1.RelayServiceGrpcKt
import java.util.concurrent.TimeUnit

class RelayClient(
    host: String,
    port: Int,
    useTls: Boolean = true
) {
    private val channel: ManagedChannel =
        OkHttpChannelBuilder.forAddress(host, port)
            .apply {
                if (useTls) useTransportSecurity() else usePlaintext()
                keepAliveTime(30, TimeUnit.SECONDS)
                keepAliveTimeout(10, TimeUnit.SECONDS)
                keepAliveWithoutCalls(true)
            }
            .build()

    val stub: RelayServiceGrpcKt.RelayServiceCoroutineStub =
        RelayServiceGrpcKt.RelayServiceCoroutineStub(channel)

    suspend fun shutdown() {
        try {
            channel.shutdownNow()
            channel.awaitTermination(3, TimeUnit.SECONDS)
        } catch (ignored: Throwable) { /* ignore */ }
    }

    companion object {
        fun isTransient(t: Throwable): Boolean {
            val s = Status.fromThrowable(t).code
            return s == Status.Code.UNAVAILABLE ||
                s == Status.Code.CANCELLED ||
                s == Status.Code.DEADLINE_EXCEEDED
        }
    }
}
