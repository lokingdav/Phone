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
import java.nio.charset.Charset
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
        "direction",
        "protocol_enabled",
        "cache_enabled",
        "rua_only_mode",
        "dia_begin_unix_ms",
        "dia_complete_unix_ms",
        "dia_duration_ms",
        "ake_begin_unix_ms",
        "ake_end_unix_ms",
        "ake_duration_ms",
        "rua_begin_unix_ms",
        "rua_end_unix_ms",
        "rua_duration_ms",
        "auto_oda_enabled",
        "auto_oda_delay_ms",
        "oda_begin_unix_ms",
        "oda_end_unix_ms",
        "oda_duration_ms",
        "oda_outcome",
        "oda_error",
        "oda_was_auto",
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
        val direction: String,
        val protocolEnabled: Boolean,
        val cacheEnabled: Boolean,
        val ruaOnlyMode: Boolean,
        val diaBeginAtUnixMs: Long,
        val diaBeginAtElapsedMs: Long,
    ) {
        @Volatile var diaCompleteAtUnixMs: Long = 0L
        @Volatile var diaCompleteAtElapsedMs: Long = 0L

        @Volatile var akeBeginAtUnixMs: Long = 0L
        @Volatile var akeBeginAtElapsedMs: Long = 0L
        @Volatile var akeEndAtUnixMs: Long = 0L
        @Volatile var akeEndAtElapsedMs: Long = 0L

        @Volatile var ruaBeginAtUnixMs: Long = 0L
        @Volatile var ruaBeginAtElapsedMs: Long = 0L
        @Volatile var ruaEndAtUnixMs: Long = 0L
        @Volatile var ruaEndAtElapsedMs: Long = 0L

        @Volatile var autoOdaEnabled: Boolean = false
        @Volatile var autoOdaDelayMs: Long = 0L

        @Volatile var odaBeginAtUnixMs: Long = 0L
        @Volatile var odaBeginAtElapsedMs: Long = 0L
        @Volatile var odaEndAtUnixMs: Long = 0L
        @Volatile var odaEndAtElapsedMs: Long = 0L
        @Volatile var odaOutcome: String = ""
        @Volatile var odaError: String = ""
        @Volatile var odaWasAuto: Boolean = false

        @Volatile var outcome: String = ""
        @Volatile var error: String = ""

        @Volatile var flushed: Boolean = false
    }

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
        // If we have a completed attempt that hasn't flushed yet (e.g. waiting on auto ODA), flush it on removal.
        incomingDiaDurationByCallKey.remove(callKey)?.let { attempt ->
            if (!attempt.flushed && attempt.diaCompleteAtElapsedMs > 0L) {
                attempt.outcome = attempt.outcome.ifBlank { "call_removed" }
                attempt.error = attempt.error.ifBlank { "removed_before_flush" }
                attempt.flushed = true
                appendIncomingDiaDurationRecord(attempt)
            }
        }
    }

    /**
     * Incoming DIA duration: marks the moment DIA begins.
     * Pair with [onIncomingDiaEnd] to compute DIA duration bounded to the protocol run.
     */
    fun onIncomingDiaBegin(call: Call, protocolEnabled: Boolean, cacheEnabled: Boolean, ruaOnlyMode: Boolean) {
        val context = appContext ?: return
        val callKey = System.identityHashCode(call)

        val nowUnixMs = System.currentTimeMillis()
        val nowElapsedMs = SystemClock.elapsedRealtime()

        val peerUri = call.details.handle?.toString().orEmpty()
        val peerPhone = call.details.handle?.schemeSpecificPart.orEmpty()
        val direction = if (call.details.callDirection == Call.Details.DIRECTION_INCOMING) "incoming" else "outgoing"

        val attempt = IncomingDiaDurationAttempt(
            attemptId = UUID.randomUUID().toString(),
            callId = callKey.toString(),
            peerPhone = peerPhone,
            peerUri = peerUri,
            direction = direction,
            protocolEnabled = protocolEnabled,
            cacheEnabled = cacheEnabled,
            ruaOnlyMode = ruaOnlyMode,
            diaBeginAtUnixMs = nowUnixMs,
            diaBeginAtElapsedMs = nowElapsedMs,
        )

        incomingDiaDurationByCallKey[callKey] = attempt
    }

    /**
     * Incoming DIA duration: records completion time and emits a CSV row.
     */
    fun onIncomingDiaEnd(call: Call, success: Boolean, error: String = "") {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return

        val doneAtUnixMs = System.currentTimeMillis()
        val doneElapsedMs = SystemClock.elapsedRealtime()

        attempt.diaCompleteAtUnixMs = doneAtUnixMs
        attempt.diaCompleteAtElapsedMs = doneElapsedMs
        attempt.outcome = if (success) "verified" else "failed"
        attempt.error = error

        maybeFlushIncomingDiaDuration(call, attempt, force = false)
    }

    fun onIncomingAkeBegin(call: Call) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.akeBeginAtElapsedMs > 0L) return
        attempt.akeBeginAtUnixMs = System.currentTimeMillis()
        attempt.akeBeginAtElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onIncomingAkeEnd(call: Call) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.akeEndAtElapsedMs > 0L) return
        attempt.akeEndAtUnixMs = System.currentTimeMillis()
        attempt.akeEndAtElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onIncomingRuaBegin(call: Call) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.ruaBeginAtElapsedMs > 0L) return
        attempt.ruaBeginAtUnixMs = System.currentTimeMillis()
        attempt.ruaBeginAtElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onIncomingRuaEnd(call: Call) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.ruaEndAtElapsedMs > 0L) return
        attempt.ruaEndAtUnixMs = System.currentTimeMillis()
        attempt.ruaEndAtElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onIncomingAutoOdaPlanned(call: Call, enabled: Boolean, delayMs: Long) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        attempt.autoOdaEnabled = enabled
        attempt.autoOdaDelayMs = delayMs
    }

    fun onIncomingOdaBegin(call: Call, wasAuto: Boolean = false) {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.odaBeginAtElapsedMs > 0L) return
        attempt.odaWasAuto = wasAuto
        attempt.odaBeginAtUnixMs = System.currentTimeMillis()
        attempt.odaBeginAtElapsedMs = SystemClock.elapsedRealtime()
    }

    fun onIncomingOdaEnd(call: Call, outcome: String, error: String = "") {
        val attempt = incomingDiaDurationByCallKey[System.identityHashCode(call)] ?: return
        if (attempt.odaEndAtElapsedMs > 0L) return
        attempt.odaEndAtUnixMs = System.currentTimeMillis()
        attempt.odaEndAtElapsedMs = SystemClock.elapsedRealtime()
        attempt.odaOutcome = outcome
        attempt.odaError = error
        maybeFlushIncomingDiaDuration(call, attempt, force = false)
    }

    private fun maybeFlushIncomingDiaDuration(call: Call, attempt: IncomingDiaDurationAttempt, force: Boolean) {
        if (attempt.flushed) return
        if (attempt.diaCompleteAtElapsedMs <= 0L) return

        val shouldWaitForOda = attempt.autoOdaEnabled
        val odaDone = attempt.odaEndAtElapsedMs > 0L

        if (!force && shouldWaitForOda && !odaDone) {
            return
        }

        attempt.flushed = true
        // Remove from map once flushed so we don't double-write.
        incomingDiaDurationByCallKey.remove(System.identityHashCode(call))
        appendIncomingDiaDurationRecord(attempt)
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
        file.parentFile?.mkdirs()

        val desiredHeaderLine = incomingDiaDurationHeader.joinToString(",") { escapeCsv(it) }

        if (!file.exists() || file.length() == 0L) {
            FileWriter(file, true).use { fw ->
                fw.append(desiredHeaderLine)
                fw.append("\n")
            }
            return
        }

        // If header already matches, nothing to do.
        val firstLine = try {
            file.inputStream().bufferedReader(Charset.forName("UTF-8")).use { it.readLine().orEmpty() }
        } catch (_: Exception) {
            ""
        }

        if (firstLine == desiredHeaderLine) {
            return
        }

        // Migrate: rewrite header and pad existing rows with extra empty columns.
        try {
            val lines = file.readLines(Charset.forName("UTF-8"))
            if (lines.isEmpty()) {
                FileWriter(file, false).use { fw ->
                    fw.append(desiredHeaderLine)
                    fw.append("\n")
                }
                return
            }

            val oldHeaderCols = lines.first().split(',').size
            val newHeaderCols = incomingDiaDurationHeader.size
            val extraCols = (newHeaderCols - oldHeaderCols).coerceAtLeast(0)

            FileWriter(file, false).use { fw ->
                fw.append(desiredHeaderLine)
                fw.append("\n")

                for (i in 1 until lines.size) {
                    val line = lines[i]
                    if (line.isBlank()) continue
                    if (extraCols == 0) {
                        fw.append(line)
                        fw.append("\n")
                    } else {
                        fw.append(line)
                        repeat(extraCols) { fw.append(',') }
                        fw.append("\n")
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed migrating incoming DIA duration CSV header: ${e.message}", e)
        }
    }

    private fun appendIncomingDiaDurationRecord(attempt: IncomingDiaDurationAttempt) {
        scope.launch {
            val context = appContext ?: return@launch
            val selfPhone = Storage.loadEnrolledPhone().orEmpty()

            val diaDurationMs = if (attempt.diaBeginAtElapsedMs > 0L && attempt.diaCompleteAtElapsedMs > 0L) {
                attempt.diaCompleteAtElapsedMs - attempt.diaBeginAtElapsedMs
            } else {
                0L
            }

            val akeDurationMs = if (attempt.akeBeginAtElapsedMs > 0L && attempt.akeEndAtElapsedMs > 0L) {
                attempt.akeEndAtElapsedMs - attempt.akeBeginAtElapsedMs
            } else {
                0L
            }

            val ruaDurationMs = if (attempt.ruaBeginAtElapsedMs > 0L && attempt.ruaEndAtElapsedMs > 0L) {
                attempt.ruaEndAtElapsedMs - attempt.ruaBeginAtElapsedMs
            } else {
                0L
            }

            val odaDurationMs = if (attempt.odaBeginAtElapsedMs > 0L && attempt.odaEndAtElapsedMs > 0L) {
                attempt.odaEndAtElapsedMs - attempt.odaBeginAtElapsedMs
            } else {
                0L
            }

            val rec = listOf(
                attempt.attemptId,
                attempt.callId,
                selfPhone,
                attempt.peerPhone,
                attempt.peerUri,
                attempt.direction,
                attempt.protocolEnabled.toString(),
                attempt.cacheEnabled.toString(),
                attempt.ruaOnlyMode.toString(),
                attempt.diaBeginAtUnixMs.toString(),
                attempt.diaCompleteAtUnixMs.toString(),
                diaDurationMs.toString(),
                attempt.akeBeginAtUnixMs.toString(),
                attempt.akeEndAtUnixMs.toString(),
                akeDurationMs.toString(),
                attempt.ruaBeginAtUnixMs.toString(),
                attempt.ruaEndAtUnixMs.toString(),
                ruaDurationMs.toString(),
                attempt.autoOdaEnabled.toString(),
                attempt.autoOdaDelayMs.toString(),
                attempt.odaBeginAtUnixMs.toString(),
                attempt.odaEndAtUnixMs.toString(),
                odaDurationMs.toString(),
                attempt.odaOutcome,
                attempt.odaError,
                attempt.odaWasAuto.toString(),
                attempt.outcome,
                attempt.error
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
