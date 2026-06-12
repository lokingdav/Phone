package org.fossify.phone.fragments

import android.app.Activity
import android.app.Dialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Status
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.fossify.phone.R
import org.fossify.phone.callerauth.AuthService
import org.fossify.phone.callerauth.Storage
import androidx.lifecycle.lifecycleScope

class EnrollmentDialogFragment : DialogFragment() {
    companion object {
        private const val SMS_OTP_WAIT_MS = 15_000L
    }


    private lateinit var phoneNumberInput: EditText
    private lateinit var displayNameInput: EditText
    private lateinit var logoUrlInput: EditText

    private lateinit var esHostInput: EditText
    private lateinit var esPortInput: EditText
    private lateinit var rsHostInput: EditText
    private lateinit var rsPortInput: EditText

    private var pendingSmsOtp: CompletableDeferred<String>? = null
    private var smsReceiverRegistered = false

    private val smsConsentLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val deferred = pendingSmsOtp ?: return@registerForActivityResult
        if (result.resultCode != Activity.RESULT_OK) {
            if (!deferred.isCompleted) {
                deferred.completeExceptionally(IllegalStateException("SMS consent was cancelled"))
            }
            return@registerForActivityResult
        }

        val message = result.data?.getStringExtra(SmsRetriever.EXTRA_SMS_MESSAGE)
        val otp = message?.let(::extractOtp)
        if (otp != null) {
            if (!deferred.isCompleted) {
                deferred.complete(otp)
            }
        } else if (!deferred.isCompleted) {
            deferred.completeExceptionally(IllegalStateException("Unable to parse OTP from SMS"))
        }
    }

    private val smsConsentReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != SmsRetriever.SMS_RETRIEVED_ACTION) {
                return
            }

            val extras = intent.extras ?: return
            val status = extras.get(SmsRetriever.EXTRA_STATUS) as? Status ?: return
            val deferred = pendingSmsOtp ?: return

            when (status.statusCode) {
                CommonStatusCodes.SUCCESS -> {
                    val consentIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        extras.getParcelable(SmsRetriever.EXTRA_CONSENT_INTENT, Intent::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        extras.getParcelable(SmsRetriever.EXTRA_CONSENT_INTENT) as? Intent
                    }

                    if (consentIntent != null) {
                        smsConsentLauncher.launch(consentIntent)
                    } else if (!deferred.isCompleted) {
                        deferred.completeExceptionally(IllegalStateException("SMS consent intent missing"))
                    }
                }

                CommonStatusCodes.TIMEOUT -> {
                    if (!deferred.isCompleted) {
                        deferred.completeExceptionally(IllegalStateException("Timed out waiting for SMS OTP"))
                    }
                }
            }
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val builder = MaterialAlertDialogBuilder(requireActivity())
        val inflater = requireActivity().layoutInflater
        val view = inflater.inflate(R.layout.dialog_enrollment, null)

        // Initialize the input fields from the layout
        phoneNumberInput = view.findViewById(R.id.phone_number_input)
        displayNameInput = view.findViewById(R.id.display_name_input)
        logoUrlInput = view.findViewById(R.id.logo_url_input)

        esHostInput = view.findViewById(R.id.es_host_input)
        esPortInput = view.findViewById(R.id.es_port_input)
        rsHostInput = view.findViewById(R.id.rs_host_input)
        rsPortInput = view.findViewById(R.id.rs_port_input)

        builder.setView(view)
            .setTitle("Device Enrollment")
            // Set the button text here, but the click listener will be overridden in onStart()
            .setPositiveButton("Enroll", null)
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.cancel()
            }

        return builder.create()
    }

    override fun onStart() {
        super.onStart()
        registerSmsReceiver()
        // Get the dialog instance and override the positive button's click listener
        val dialog = dialog as? AlertDialog

        if (org.fossify.phone.BuildConfig.DEBUG) {
            phoneNumberInput.setText("2001")
            displayNameInput.setText("Bob Farber")
            logoUrlInput.setText("https://i.pravatar.cc/150?img=${(1..100).random()}")
        }

        // Prefill current effective values for convenience.
        // Users can clear a field to revert to BuildConfig defaults.
        esHostInput.setText(Storage.getEffectiveEsHost())
        esPortInput.setText(Storage.getEffectiveEsPort().toString())
        rsHostInput.setText(Storage.getEffectiveRsHost())
        rsPortInput.setText(Storage.getEffectiveRsPort().toString())

        dialog?.let {
            val positiveButton: Button = it.getButton(Dialog.BUTTON_POSITIVE)
            positiveButton.setOnClickListener {
                // Get the text from all fields
                val phoneNumber = phoneNumberInput.text.toString()
                val displayName = displayNameInput.text.toString()
                val logoUrl = logoUrlInput.text.toString()

                val esHostRaw = esHostInput.text.toString().trim()
                val esPortRaw = esPortInput.text.toString().trim()
                val rsHostRaw = rsHostInput.text.toString().trim()
                val rsPortRaw = rsPortInput.text.toString().trim()

                // Reset previous errors
                phoneNumberInput.error = null
                displayNameInput.error = null
                logoUrlInput.error = null
                esHostInput.error = null
                esPortInput.error = null
                rsHostInput.error = null
                rsPortInput.error = null

                var isValid = true

                // Perform validation on each field
                if (phoneNumber.isBlank()) {
                    phoneNumberInput.error = "Phone number cannot be empty."
                    isValid = false
                }

                if (displayName.isBlank()) {
                    displayNameInput.error = "Display name cannot be empty."
                    isValid = false
                }

                if (logoUrl.isBlank()) {
                    logoUrlInput.error = "Logo URL cannot be empty."
                    isValid = false
                }

                val esPort = esPortRaw.toIntOrNull()
                val rsPort = rsPortRaw.toIntOrNull()

                if (esHostRaw.isNotBlank() && (esPort == null || esPort !in 1..65535)) {
                    esPortInput.error = "Invalid ES port (1-65535)."
                    isValid = false
                }

                if (rsHostRaw.isNotBlank() && (rsPort == null || rsPort !in 1..65535)) {
                    rsPortInput.error = "Invalid RS port (1-65535)."
                    isValid = false
                }

                // If all fields are valid, proceed and close the dialog
                if (isValid) {
                    val smsEnabled = Storage.isEnrollmentSmsEnabled()

                    // Persist server overrides before enrolling.
                    // Blank host clears the override and reverts to BuildConfig defaults.
                    Storage.saveEsHostOverride(esHostRaw.ifBlank { null })
                    Storage.saveEsPortOverride(if (esHostRaw.isBlank()) null else esPort)
                    Storage.saveRsHostOverride(rsHostRaw.ifBlank { null })
                    Storage.saveRsPortOverride(if (rsHostRaw.isBlank()) null else rsPort)

                    // Disable button during enrollment to prevent multiple submissions
                    positiveButton.isEnabled = false
                    positiveButton.text = "Enrolling..."

                    if (smsEnabled) {
                        beginSmsOtpCapture()
                    }

                    // Call enrollment service (runs in background scope)
                    AuthService.enrollNewNumber(
                        phoneNumber = phoneNumber,
                        displayName = displayName,
                        logoUrl     = logoUrl,
                        otpProvider = { fallbackOtp -> resolveEnrollmentOtp(smsEnabled, fallbackOtp) },
                        onComplete = { success, error ->
                            lifecycleScope.launch(Dispatchers.Main) {
                                dismiss() // Close dialog first
                                if (success) {
                                    Toast.makeText(requireContext(), "Enrollment successful!", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(requireContext(), "Enrollment failed: $error", Toast.LENGTH_LONG).show()
                                }
                            }
                        }
                    )
                }
            }
        }
    }

    override fun onStop() {
        unregisterSmsReceiver()
        super.onStop()
    }

    private fun beginSmsOtpCapture() {
        pendingSmsOtp?.cancel()
        pendingSmsOtp = CompletableDeferred()

        SmsRetriever.getClient(requireContext())
            .startSmsUserConsent(null)
            .addOnFailureListener { error ->
                pendingSmsOtp?.let { deferred ->
                    if (!deferred.isCompleted) {
                        deferred.completeExceptionally(error)
                    }
                }
            }
    }

    private suspend fun resolveEnrollmentOtp(smsEnabled: Boolean, fallbackOtp: String?): String {
        fallbackOtp?.takeIf { it.isNotBlank() }?.let { return it }
        if (!smsEnabled) {
            throw IllegalStateException("Enrollment server did not return an OTP while SMS mode is disabled")
        }

        return try {
            awaitSmsOtp()
        } catch (_: Exception) {
            promptForOtpManually()
        }
    }

    private suspend fun awaitSmsOtp(): String {
        val deferred = pendingSmsOtp ?: throw IllegalStateException("SMS OTP capture was not started")
        return withContext(Dispatchers.Main) {
            withTimeout(SMS_OTP_WAIT_MS) {
                deferred.await()
            }
        }
    }

    private fun extractOtp(message: String): String? {
        return Regex("\\b\\d{4,8}\\b").find(message)?.value
    }

    private suspend fun promptForOtpManually(): String = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { continuation ->
            val input = EditText(requireContext()).apply {
                inputType = InputType.TYPE_CLASS_NUMBER
                hint = "OTP code"
            }

            val dialog = MaterialAlertDialogBuilder(requireContext())
                .setTitle("Enter OTP")
                .setMessage("Automatic SMS detection did not complete. Enter the OTP manually to continue enrollment.")
                .setView(input)
                .setCancelable(false)
                .setPositiveButton("Continue", null)
                .setNegativeButton("Cancel") { _, _ ->
                    if (continuation.isActive) {
                        continuation.resumeWith(Result.failure(IllegalStateException("OTP entry cancelled")))
                    }
                }
                .create()

            dialog.setOnShowListener {
                val positiveButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                positiveButton.setOnClickListener {
                    val otp = input.text.toString().trim()
                    if (otp.isBlank()) {
                        input.error = "OTP is required"
                        return@setOnClickListener
                    }
                    if (continuation.isActive) {
                        continuation.resumeWith(Result.success(otp))
                    }
                    dialog.dismiss()
                }
            }

            continuation.invokeOnCancellation {
                dialog.dismiss()
            }

            dialog.show()
        }
    }

    private fun registerSmsReceiver() {
        if (smsReceiverRegistered) {
            return
        }

        val filter = IntentFilter(SmsRetriever.SMS_RETRIEVED_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireContext().registerReceiver(smsConsentReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            requireContext().registerReceiver(smsConsentReceiver, filter)
        }
        smsReceiverRegistered = true
    }

    private fun unregisterSmsReceiver() {
        if (!smsReceiverRegistered) {
            return
        }

        requireContext().unregisterReceiver(smsConsentReceiver)
        smsReceiverRegistered = false
    }
}
