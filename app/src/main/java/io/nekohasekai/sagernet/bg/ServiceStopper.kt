package io.nekohasekai.sagernet.bg

import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.ISagerNetService
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Do not restore databases while the old service can still persist traffic. */
object ServiceStopper {
    suspend fun stopAndWait() {
        // The mode preference can already differ from the class of the running service.
        stopAndWait(VpnService::class.java)
        stopAndWait(ProxyService::class.java)
    }

    private suspend fun stopAndWait(serviceClass: Class<*>) {
        val stopped = CompletableDeferred<Unit>()
        val connection = SagerConnection(SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_BACKGROUND, true, serviceClass)
        try {
            onMainDispatcher {
                connection.connect(app, object : SagerConnection.Callback {
                    override fun onServiceConnected(service: ISagerNetService) {
                        SagerNet.stopService()
                        if (service.state == BaseService.State.Stopped.ordinal) stopped.complete(Unit)
                    }
                    override fun stateChanged(state: BaseService.State, profileName: String?, msg: String?) {
                        if (state == BaseService.State.Stopped) stopped.complete(Unit)
                    }
                    override fun onBinderDied() {
                        stopped.completeExceptionally(IllegalStateException("Service died during restore preparation; retry after restarting the app"))
                    }
                })
            }
            withTimeout(45_000) { stopped.await() }
        } finally {
            withContext(NonCancellable) { onMainDispatcher { connection.disconnect(app) } }
        }
    }
}
