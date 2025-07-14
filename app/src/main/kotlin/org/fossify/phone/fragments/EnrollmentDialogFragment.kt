package org.fossify.phone.fragments

import android.app.Dialog
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.DialogFragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.fossify.phone.R
import org.fossify.phone.helpers.DenseIdentity

class EnrollmentDialogFragment : DialogFragment() {

    private lateinit var phoneNumberInput: EditText
    private lateinit var displayNameInput: EditText
    private lateinit var logoUrlInput: EditText

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val builder = MaterialAlertDialogBuilder(requireActivity())
        val inflater = requireActivity().layoutInflater
        val view = inflater.inflate(R.layout.dialog_enrollment, null)

        // Initialize the input fields from the layout
        phoneNumberInput = view.findViewById(R.id.phone_number_input)
        displayNameInput = view.findViewById(R.id.display_name_input)
        logoUrlInput = view.findViewById(R.id.logo_url_input)

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
            phoneNumberInput.setText("+15551234567")
            displayNameInput.setText("Janet Doeyer")
            logoUrlInput.setText("https://avatar.iran.liara.run/public/54")
        }

        dialog?.let {
            val positiveButton: Button = it.getButton(Dialog.BUTTON_POSITIVE)
            positiveButton.setOnClickListener {
                // Get the text from all fields
                val phoneNumber = phoneNumberInput.text.toString()
                val displayName = displayNameInput.text.toString()
                val logoUrl = logoUrlInput.text.toString()

                // Reset previous errors
                phoneNumberInput.error = null
                displayNameInput.error = null
                logoUrlInput.error = null

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

                // If all fields are valid, proceed and close the dialog
                if (isValid) {
                    val message = "Enrolling:\nPhone: $phoneNumber\nName: $displayName\nLogo: $logoUrl"
                    Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show()
                    DenseIdentity.enrollNewNumber(phoneNumber, displayName, logoUrl)
                    dismiss() // Manually dismiss the dialog on success
                }
            }
        }
    }
}
