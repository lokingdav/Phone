package org.fossify.phone.metrics

import android.content.Context
import android.os.SystemClock
import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.fossify.phone.App
import org.fossify.phone.callerauth.Storage
import org.fossify.phone.extensions.config
import java.io.File
import java.io.FileWriter
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

object MetricsRecorder {
    private const val TAG = "DIA-Metrics"
    private const val FILE_NAME = "denseid_results.csv"
    private const val INCOMING_DIA_DURATION_FILE_NAME = "denseid_incoming_dia_duration.csv"

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val fileLock = Any()

    @Volatile
    private var appContext: Context? = null

    private val header = listOf(
        "attempt_id",
        "call_id",
        "self_phone",
        "peer_phone",
        "peer_uri",
        "direction",
        "protocol_enabled",
        "dial_sent_unix_ms",
        "answered_unix_ms",
        "latency_ms",
        "oda_requested_unix_ms",
        "oda_completed_unix_ms",
        "oda_latency_ms",
        "outcome",
        "error"
    )

    private val incomingDiaDurationHeader = listOf(
        "attempt_id",
        "call_id",
        "self_phone",
        "peer_phone",
        "peer_uri",
        "protocol_enabled",
        "cache_enabled",
        "dia_begin_unix_ms",
        "dia_complete_unix_ms",
        "dia_duration_ms",
        "outcome",
        "error"
    )

    data class AttemptContext(
        val attemptId: String,
        val direction: String,
        val protocolEnabled: Boolean,
        val peerPhone: String,
        val peerUri: String,
        val dialSentAtUnixMs: Long,
        val dialSentElapsedMs: Long,
    ) {
        @Volatile var callId: String = ""
        @Volatile var answeredAtUnixMs: Long = 0L
        @Volatile var answeredEmitted: Boolean = false

        @Volatile var odaRequestedAtUnixMs: Long = 0L
        @Volatile var odaRequestedElapsedMs: Long = 0L
    }

    data class IncomingDiaDurationAttempt(
        val attemptId: String,
        val callId: String,
        val peerPhone: String,
        val peerUri: String,
        val protocolEnabled: Boolean,
        val cacheEnabled: Boolean,
        val diaBeginAtUnixMs: Long,
        val diaBeginAtElapsedMs: Long,
    )

    private val pendingOutgoingByPeer = ConcurrentHashMap<String, ConcurrentLinkedQueue<AttemptContext>>()
    private val activeByCallKey = ConcurrentHashMap<Int, AttemptContext>()
    private val incomingDiaDurationByCallKey = ConcurrentHashMap<Int, IncomingDiaDurationAttempt>()

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    fun clearResults(context: Context): Boolean {
        synchronized(fileLock) {
            return try {
                val appCtx = context.applicationContext

                val resultsOk = run {
                    val file = resultsFile(appCtx)
                    !file.exists() || file.delete()
                }

                val incomingDiaDurationOk = run {
                    val file = incomingDiaDurationFile(appCtx)
                    !file.exists() || file.delete()
                }

                resultsOk && incomingDiaDurationOk
            } catch (e: Exception) {
                Log.w(TAG, "Failed clearing results: ${e.message}", e)
                false
            }
        }
    }

    /**
     * Directory where DIA CSV artifacts are written.
     * This is the same location used for [denseid_results.csv].
     */
    fun resultsDir(context: Context): File {
        val appCtx = context.applicationContext
        return appCtx.getExternalFilesDir(null) ?: appCtx.filesDir
    }

    fun markOutgoingDial(peerPhone: String, protocolEnabled: Boolean) {
        val nowUnixMs = System.currentTimeMillis()
        val nowElapsedMs = SystemClock.elapsedRealtime()
        val attempt = AttemptContext(
            attemptId = UUID.randomUUID().toString(),
            direction = "outgoing",
            protocolEnabled = protocolEnabled,
            peerPhone = peerPhone,
            peerUri = "tel:$peerPhone",
            dialSentAtUnixMs = nowUnixMs,
            dialSentElapsedMs = nowElapsedMs
        )

        val key = normalizePhone(peerPhone)
        pendingOutgoingByPeer.getOrPut(key) { ConcurrentLinkedQueue() }.add(attempt)
    }

    fun onCallAdded(call: Call) {
        val context = appContext ?: return
        val callKey = System.identityHashCode(call)

        val direction = if (call.details.callDirection == Call.Details.DIRECTION_INCOMING) "incoming" else "outgoing"
        val peerUri = call.details.handle?.toString().orEmpty()
        val peerPhone = call.details.handle?.schemeSpecificPart.orEmpty()

        if (direction == "outgoing") {
            val pending = pendingOutgoingByPeer[normalizePhone(peerPhone)]?.poll()
            val attempt = pending ?: AttemptContext(
                attemptId = UUID.randomUUID().toString(),
                direction = "outgoing",
                protocolEnabled = (App.diaConfig != null && context.config.diaProtocolEnabled),
                peerPhone = peerPhone,
                peerUri = peerUri,
                dialSentAtUnixMs = 0L,
                dialSentElapsedMs = 0L
            )

            attempt.callId = callKey.toString()
            activeByCallKey[callKey] = attempt
            return
        }

        // Incoming: create context for potential ODA measurements (no setup latency row).
        val attempt = AttemptContext(
            attemptId = UUID.randomUUID().toString(),
            direction = "incoming",
            protocolEnabled = (App.diaConfig != null && context.config.diaProtocolEnabled),
            peerPhone = peerPhone,
            peerUri = peerUri,
            dialSentAtUnixMs = 0L,
            dialSentElapsedMs = 0L
        )
        attempt.callId = callKey.toString()
        activeByCallKey[callKey] = attempt
    }

    fun onCallAnswered(call: Call) {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        if (attempt.direction != "outgoing") {
            return
        }
        if (attempt.answeredEmitted) {
            return
        }
        if (attempt.dialSentAtUnixMs <= 0L) {
            return
        }

        val answeredAtUnixMs = System.currentTimeMillis()
        val answeredElapsedMs = SystemClock.elapsedRealtime()
        attempt.answeredAtUnixMs = answeredAtUnixMs
        attempt.answeredEmitted = true

        val latencyMs = if (attempt.dialSentElapsedMs > 0L) answeredElapsedMs - attempt.dialSentElapsedMs else 0L
        appendRecord(
            attempt = attempt,
            answeredAtUnixMs = answeredAtUnixMs,
            latencyMs = latencyMs,
            outcome = "answered",
            error = ""
        )
    }

    fun onCallRemoved(call: Call) {
        val callKey = System.identityHashCode(call)
        activeByCallKey.remove(callKey)
        incomingDiaDurationByCallKey.remove(callKey)
    }

    /**
     * Incoming DIA duration: marks the moment DIA begins.
     * Pair with [onIncomingDiaEnd] to compute DIA duration bounded to the protocol run.
     */
    fun onIncomingDiaBegin(call: Call, protocolEnabled: Boolean, cacheEnabled: Boolean) {
        val context = appContext ?: return
        val callKey = System.identityHashCode(call)

        val nowUnixMs = System.currentTimeMillis()
        val nowElapsedMs = SystemClock.elapsedRealtime()

        val peerUri = call.details.handle?.toString().orEmpty()
        val peerPhone = call.details.handle?.schemeSpecificPart.orEmpty()

        val attempt = IncomingDiaDurationAttempt(
            attemptId = UUID.randomUUID().toString(),
            callId = callKey.toString(),
            peerPhone = peerPhone,
            peerUri = peerUri,
            protocolEnabled = protocolEnabled,
            cacheEnabled = cacheEnabled,
            diaBeginAtUnixMs = nowUnixMs,
            diaBeginAtElapsedMs = nowElapsedMs,
        )

        incomingDiaDurationByCallKey[callKey] = attempt
    }

    /**
     * Incoming DIA duration: records completion time and emits a CSV row.
     */
    fun onIncomingDiaEnd(call: Call, success: Boolean, error: String = "") {
        val attempt = incomingDiaDurationByCallKey.remove(System.identityHashCode(call)) ?: return

        val doneAtUnixMs = System.currentTimeMillis()
        val doneElapsedMs = SystemClock.elapsedRealtime()
        val durationMs = if (attempt.diaBeginAtElapsedMs > 0L) doneElapsedMs - attempt.diaBeginAtElapsedMs else 0L

        val outcome = if (success) "verified" else "failed"
        appendIncomingDiaDurationRecord(
            attempt = attempt,
            doneAtUnixMs = doneAtUnixMs,
            durationMs = durationMs,
            outcome = outcome,
            error = error
        )
    }


    fun onOdaRequested(call: Call) {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        attempt.odaRequestedAtUnixMs = System.currentTimeMillis()
        attempt.odaRequestedElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onOdaCompleted(call: Call, outcome: String, error: String = "") {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        val reqAt = attempt.odaRequestedAtUnixMs
        val reqElapsed = attempt.odaRequestedElapsedMs
        if (reqAt <= 0L) {
            return
        }

        val doneAtUnixMs = System.currentTimeMillis()
        val doneElapsedMs = SystemClock.elapsedRealtime()
        val odaLatencyMs = if (reqElapsed > 0L) doneElapsedMs - reqElapsed else 0L
        appendRecord(
            attempt = attempt,
            odaReqUnixMs = reqAt,
            odaDoneUnixMs = doneAtUnixMs,
            odaLatencyMs = odaLatencyMs,
            outcome = outcome,
            error = error
        )

        attempt.odaRequestedAtUnixMs = 0L
        attempt.odaRequestedElapsedMs = 0L
    }

    private fun appendRecord(
        attempt: AttemptContext,
        answeredAtUnixMs: Long = 0L,
        latencyMs: Long = 0L,
        odaReqUnixMs: Long = 0L,
        odaDoneUnixMs: Long = 0L,
        odaLatencyMs: Long = 0L,
        outcome: String,
        error: String,
    ) {
        scope.launch {
            val context = appContext ?: return@launch
            val selfPhone = Storage.loadEnrolledPhone().orEmpty()

            val rec = listOf(
                attempt.attemptId,
                attempt.callId,
                selfPhone,
                attempt.peerPhone,
                attempt.peerUri,
                attempt.direction,
                attempt.protocolEnabled.toString(),
                attempt.dialSentAtUnixMs.toString(),
                answeredAtUnixMs.toString(),
                latencyMs.toString(),
                odaReqUnixMs.toString(),
                odaDoneUnixMs.toString(),
                odaLatencyMs.toString(),
                outcome,
                error
            )

            synchronized(fileLock) {
                try {
                    val file = resultsFile(context)
                    ensureHeader(file)
                    FileWriter(file, true).use { fw ->
                        fw.append(rec.joinToString(",") { escapeCsv(it) })
                        fw.append("\n")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "CSV write failed: ${e.message}", e)
                }
            }
        }
    }

    private fun resultsFile(context: Context): File = File(resultsDir(context), FILE_NAME)

    private fun incomingDiaDurationFile(context: Context): File = File(resultsDir(context), INCOMING_DIA_DURATION_FILE_NAME)

    private fun ensureHeader(file: File) {
        if (file.exists() && file.length() > 0) {
            return
        }
        file.parentFile?.mkdirs()
        FileWriter(file, true).use { fw ->
            fw.append(header.joinToString(",") { escapeCsv(it) })
            fw.append("\n")
        }
    }

    private fun ensureIncomingDiaDurationHeader(file: File) {
        if (file.exists() && file.length() > 0) {
            return
        }
        file.parentFile?.mkdirs()
        FileWriter(file, true).use { fw ->
            fw.append(incomingDiaDurationHeader.joinToString(",") { escapeCsv(it) })
            fw.append("\n")
        }
    }

    private fun appendIncomingDiaDurationRecord(
        attempt: IncomingDiaDurationAttempt,
        doneAtUnixMs: Long,
        durationMs: Long,
        outcome: String,
        error: String,
    ) {
        scope.launch {
            val context = appContext ?: return@launch
            val selfPhone = Storage.loadEnrolledPhone().orEmpty()

            val rec = listOf(
                attempt.attemptId,
                attempt.callId,
                selfPhone,
                attempt.peerPhone,
                attempt.peerUri,
                attempt.protocolEnabled.toString(),
                attempt.cacheEnabled.toString(),
                attempt.diaBeginAtUnixMs.toString(),
                doneAtUnixMs.toString(),
                durationMs.toString(),
                outcome,
                error
            )

            synchronized(fileLock) {
                try {
                    val file = incomingDiaDurationFile(context)
                    ensureIncomingDiaDurationHeader(file)
                    FileWriter(file, true).use { fw ->
                        fw.append(rec.joinToString(",") { escapeCsv(it) })
                        fw.append("\n")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Incoming DIA duration CSV write failed: ${e.message}", e)
                }
            }
        }
    }

    private fun escapeCsv(value: String): String {
        val needsQuoting = value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r')
        if (!needsQuoting) {
            return value
        }
        return "\"${value.replace("\"", "\"\"")}\""
    }

    private fun normalizePhone(phone: String): String {
        return phone.filter { it.isDigit() }
    }
}
