package org.fossify.phone.callerauth

import com.google.protobuf.ByteString
import denseid.relay.v1.Relay
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RelaySession(
    private val client: RelayClient,
    private val topic: String,
    private val ticket: ByteArray?,
    private val scope: CoroutineScope
) {
    private val reconnectBackoffMs = longArrayOf(0L, 500L, 1000L, 2000L, 5000L)

    fun startReceiving(onMessage: (ByteArray) -> Unit) {
        scope.launch(Dispatchers.IO) {
            var attempt = 0
            while (isActive) {
                try {
                    val req = Relay.SubscribeRequest.newBuilder()
                        .setTopic(topic)
                        .setTicket(ByteString.copyFrom(ticket))
                        .build()

                    client.stub.subscribe(req).collect { relayMsg ->
                        onMessage(relayMsg.payload.toByteArray())
                        attempt = 0
                    }
                } catch (t: Throwable) {
                    if (!RelayClient.isTransient(t)) {
                        // for POC, keep retrying anyway
                    }
                }
                val idx = attempt.coerceAtMost(reconnectBackoffMs.lastIndex)
                delay(reconnectBackoffMs[idx])
                attempt++
            }
        }
    }

    suspend fun send(payload: ByteArray): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val msg = Relay.RelayMessage.newBuilder()
                .setTopic(topic)
                .setPayload(ByteString.copyFrom(payload))
                .build()
            val resp = client.stub.publish(msg)
            resp.status.isNullOrEmpty() || resp.status.equals("OK", ignoreCase = true)
        }.getOrElse { false }
    }
}

