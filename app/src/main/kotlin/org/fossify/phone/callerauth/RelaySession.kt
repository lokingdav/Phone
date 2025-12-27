package org.fossify.phone.callerauth

import com.google.protobuf.ByteString
import denseid.relay.v1.Relay
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

class RelaySession(
    private val client: RelayClient,
    private val topic: String,
    private val ticket: ByteArray?,
    private val scope: CoroutineScope
) {
    private val reconnectBackoffMs = longArrayOf(0L, 500L, 1000L, 2000L, 5000L)
    private val senderId = UUID.randomUUID().toString()

    // Flow to send outgoing requests through the tunnel
    private val outgoingRequests = MutableSharedFlow<Relay.RelayRequest>(extraBufferCapacity = 64)

    fun startReceiving(onMessage: (ByteArray) -> Unit) {
        scope.launch(Dispatchers.IO) {
            var attempt = 0
            while (isActive) {
                try {
                    // Create subscribe request
                    val builder = Relay.RelayRequest.newBuilder()
                        .setSenderId(senderId)
                        .setType(Relay.RelayRequest.Type.SUBSCRIBE)
                        .setTopic(topic)
                    
                    val ticketBytes = ticket
                    if (ticketBytes != null) {
                        builder.setTicket(ByteString.copyFrom(ticketBytes))
                    }
                    val subscribeReq = builder.build()

                    // Emit subscribe request first, then any outgoing messages
                    val requestFlow = kotlinx.coroutines.flow.flow {
                        emit(subscribeReq)
                        outgoingRequests.asSharedFlow().collect { emit(it) }
                    }

                    client.stub.tunnel(requestFlow).collect { response ->
                        when (response.type) {
                            Relay.RelayResponse.Type.EVENT -> {
                                onMessage(response.payload.toByteArray())
                                attempt = 0
                            }
                            Relay.RelayResponse.Type.ERROR -> {
                                // Log error but continue
                            }
                            else -> { /* ignore */ }
                        }
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
            val req = Relay.RelayRequest.newBuilder()
                .setSenderId(senderId)
                .setType(Relay.RelayRequest.Type.PUBLISH)
                .setTopic(topic)
                .setPayload(ByteString.copyFrom(payload))
                .build()
            outgoingRequests.emit(req)
            true
        }.getOrElse { false }
    }
}

