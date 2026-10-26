package io.nekohasekai.sagernet.bg

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
import android.os.PowerManager
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import io.nekohasekai.sagernet.ktx.onMainDispatcher
import kotlinx.coroutines.*
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.onIoDispatcher

class ProxyService : Service(), BaseService.Interface {
    override val data = BaseService.Data(this)
    override val tag: String get() = "SagerNetProxyService"
    override fun createNotification(profileName: String): ServiceNotification =
        ServiceNotification(this, profileName, "service-proxy", true)

    override var wakeLock: PowerManager.WakeLock? = null
    override var upstreamInterfaceName: String? = null

    @SuppressLint("WakelockTimeout")
    override fun acquireWakeLock() {
        wakeLock = SagerNet.power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sagernet:proxy")
            .apply { acquire() }
    }

    private var tunnelMonitor: Job? = null

    override suspend fun startProcesses() {
        // remove leftover rules (e.g. after a crash) before anything else
        onIoDispatcher { Transproxy.cleanup() }
        super.startProcesses()
        // root transparent proxy: hev-socks5-tunnel forwards the captured traffic to the mixed inbound
        if (DataStore.serviceMode == Key.MODE_TRANS) {
            onIoDispatcher { Transproxy.start() }
            tunnelMonitor = runOnDefaultDispatcher {
                while (isActive) {
                    delay(2000)
                    if (onIoDispatcher { Transproxy.tunnelFailed() }) {
                        onMainDispatcher { stopRunner(false, getString(R.string.transproxy_tunnel_exited)) }
                        break
                    }
                }
            }
        }
    }

    override suspend fun killProcesses() {
        tunnelMonitor?.cancel()
        tunnelMonitor = null
        try { onIoDispatcher { Transproxy.cleanup() } }
        finally { super.killProcesses() }
    }

    override fun onBind(intent: Intent) = super.onBind(intent)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        super<BaseService.Interface>.onStartCommand(intent, flags, startId)
}
