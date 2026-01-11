package org.fossify.phone.fragments

import android.app.Dialog
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.fossify.phone.R
import org.fossify.phone.callerauth.AuthService
import org.fossify.phone.callerauth.Storage
import androidx.lifecycle.lifecycleScope

class EnrollmentDialogFragment : DialogFragment() {

    private lateinit var phoneNumberInput: EditText
    private lateinit var displayNameInput: EditText
    private lateinit var logoUrlInput: EditText

    private lateinit var esHostInput: EditText
    private lateinit var esPortInput: EditText
    private lateinit var rsHostInput: EditText
    private lateinit var rsPortInput: EditText

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
                    // Persist server overrides before enrolling.
                    // Blank host clears the override and reverts to BuildConfig defaults.
                    Storage.saveEsHostOverride(esHostRaw.ifBlank { null })
                    Storage.saveEsPortOverride(if (esHostRaw.isBlank()) null else esPort)
                    Storage.saveRsHostOverride(rsHostRaw.ifBlank { null })
                    Storage.saveRsPortOverride(if (rsHostRaw.isBlank()) null else rsPort)

                    // Disable button during enrollment to prevent multiple submissions
                    positiveButton.isEnabled = false
                    positiveButton.text = "Enrolling..."

                    // Call enrollment service (runs in background scope)
                    AuthService.enrollNewNumber(
                        phoneNumber = phoneNumber,
                        displayName = displayName,
                        logoUrl     = logoUrl,
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
}
