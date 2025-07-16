package org.fossify.phone

import org.fossify.commons.FossifyApp
import org.fossify.phone.helpers.DenseIdentityCallState
import org.fossify.phone.helpers.DenseIdentityStore
import java.security.Security

// Wrapper class around the FossifyApp class to initialize the DenseIdentityStore.
class App : FossifyApp() {
    var denseIdState: DenseIdentityCallState? = null

    override fun onCreate() {
        // IMPORTANT: Call the parent's onCreate() first to run its setup logic.
        super.onCreate()

        DenseIdentityStore.init(this)
        denseIdState = DenseIdentityCallState.load()
    }
}
