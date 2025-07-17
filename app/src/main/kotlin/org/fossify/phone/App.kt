package org.fossify.phone

import org.fossify.commons.FossifyApp
import org.fossify.phone.helpers.DenseIdentityCallState
import org.fossify.phone.helpers.DenseIdentityStore
import org.fossify.phone.helpers.Signing

class App : FossifyApp() {
    var denseIdState: DenseIdentityCallState? = null

    override fun onCreate() {
        super.onCreate()

        Signing.initGroupSignatures()
        DenseIdentityStore.init(this)
        denseIdState = DenseIdentityCallState.load()
    }
}
