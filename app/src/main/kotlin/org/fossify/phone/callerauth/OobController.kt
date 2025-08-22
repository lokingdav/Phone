package org.fossify.phone.callerauth

import kotlinx.coroutines.CoroutineScope

class OobController(
    host: String,
    port: Int,
    topic: String,
    ticket: ByteArray?,
    scope: CoroutineScope,
    useTls: Boolean = true
) {
    private val client = RelayClient(host, port, useTls)
    private val session = RelaySession(client, topic, ticket, scope)

    fun start(onMessage: (ByteArray) -> Unit) {
        session.startReceiving(onMessage)
    }

    suspend fun send(bytes: ByteArray): Boolean = session.send(bytes)

    suspend fun close() = client.shutdown()
}
