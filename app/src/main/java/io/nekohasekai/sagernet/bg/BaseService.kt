package io.nekohasekai.sagernet.bg

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Network
import android.net.NetworkCapabilities
import android.net.LinkProperties
import android.os.*
import android.widget.Toast
import io.nekohasekai.sagernet.Action
import io.nekohasekai.sagernet.BootReceiver
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.ISagerNetService
import io.nekohasekai.sagernet.aidl.ISagerNetServiceCallback
import io.nekohasekai.sagernet.bg.proto.ProxyInstance
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.plugin.PluginManager
import io.nekohasekai.sagernet.utils.DefaultNetworkListener
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import libcore.Libcore
import moe.matsuri.nb4a.Protocols
import moe.matsuri.nb4a.utils.Util
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap

class BaseService {

    companion object {
        // screen on, device idle exit and Wi-Fi reconnect often happen together, reset only once
        const val WAKE_RESET_DEBOUNCE = 5 * 1000L
    }

    enum class State(
        val canStop: Boolean = false,
        val started: Boolean = false,
        val connected: Boolean = false,
    ) {
        /**
         * Idle state is only used by UI and will never be returned by BaseService.
         */
        Idle, Connecting(true, true, false), Connected(true, true, true), Stopping, Stopped,
    }

    interface ExpectedException

    class Data internal constructor(private val service: Interface) {
        var state = State.Stopped
        var proxy: ProxyInstance? = null
        var notification: ServiceNotification? = null
        var upstreamNetwork: Network? = null
        var upstreamLinkProperties: LinkProperties? = null
        var upstreamNetworkLost = false

        // a new key per run: the async stop of the last run must not remove this run's listener
        var networkListenerKey: Any? = null
        var screenOffAt = 0L
        // called from the main thread and, before API 26, the connectivity thread
        private val resetter = ConnectionResetter(
            WAKE_RESET_DEBOUNCE,
            SystemClock::elapsedRealtime,
            { runOnDefaultDispatcher { it.run() } },
        ) { Libcore.resetAllConnections(true) }.apply {
            onError = { Logs.w(it) }
        }

        /**
         * @param force network changed: always reset, connections made on the old network are dead
         */
        fun resetConnections(reason: String, force: Boolean) {
            if (resetter.request(force)) {
                Logs.d("$reason, reset connections")
            } else {
                Logs.d("$reason, skip reset connections (just reset)")
            }
        }

        val receiver = broadcastReceiver { ctx, intent ->
            when (intent.action) {
                Intent.ACTION_SHUTDOWN -> service.persistStats()
                Action.RELOAD -> service.reload()
                // Action.SWITCH_WAKE_LOCK -> runOnDefaultDispatcher { service.switchWakeLock() }
                PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        // Pausing the core takes WireGuard down and stops timers for all of Doze,
                        // which drops push connections, so it is opt-in. wake() is still sent:
                        // the setting may have changed while idle, and Wake is a no-op if not paused.
                        if (SagerNet.power.isDeviceIdleMode) {
                            if (DataStore.pauseCoreInDoze) {
                                proxy?.takeIf { it.isInitialized() }?.box?.sleep()
                            }
                        } else {
                            proxy?.takeIf { it.isInitialized() }?.box?.wake()
                            if (DataStore.wakeResetConnections) {
                                resetConnections("Device wake from idle", false)
                            }
                        }
                    }
                }

                // Some ROMs cut network of background apps when the screen is off without
                // entering device idle mode, so connections may be dead after a long screen off.
                Intent.ACTION_SCREEN_OFF -> screenOffAt = SystemClock.elapsedRealtime()
                Intent.ACTION_SCREEN_ON -> {
                    val offAt = screenOffAt
                    screenOffAt = 0L
                    if (offAt > 0L && DataStore.wakeResetConnections &&
                        SystemClock.elapsedRealtime() - offAt >= DataStore.screenOffResetSeconds * 1000L
                    ) {
                        resetConnections("Screen on after long screen off", false)
                    }
                }

                Action.RESET_UPSTREAM_CONNECTIONS -> runOnDefaultDispatcher {
                    Libcore.resetAllConnections(true)
                    runOnMainDispatcher {
                        Util.collapseStatusBar(ctx)
                        Toast.makeText(ctx, "Reset upstream connections done", Toast.LENGTH_SHORT)
                            .show()
                    }
                }

                else -> service.stopRunner()
            }
        }
        var closeReceiverRegistered = false

        val binder = Binder(this)
        var connectingJob: Job? = null

        // start again when the running stop finishes: set by a restart, or by a start request
        // that came in while stopping; a plain stop request clears it
        var restartAfterStop = false

        fun changeState(s: State, msg: String? = null) {
            if (state == s && msg == null) return
            state = s
            DataStore.serviceState = s
            binder.stateChanged(s, msg)
            TileService.requestUpdate(service as Context)
        }
    }

    class Binder(private var data: Data? = null) : ISagerNetService.Stub(), CoroutineScope,
        AutoCloseable {
        private val callbacks = object : RemoteCallbackList<ISagerNetServiceCallback>() {
            override fun onCallbackDied(callback: ISagerNetServiceCallback?, cookie: Any?) {
                super.onCallbackDied(callback, cookie)
                callback?.let { callbackIdMap.remove(it.asBinder()) }
            }
        }

        // keyed by binder: every IPC call creates a new proxy object for the same callback,
        // and this map is accessed from binder threads and TrafficLooper concurrently
        val callbackIdMap = ConcurrentHashMap<IBinder, Int>()

        override val coroutineContext = Dispatchers.Main.immediate + Job()

        override fun getState(): Int = (data?.state ?: State.Idle).ordinal
        override fun getProfileName(): String = data?.proxy?.displayProfileName ?: "Idle"

        override fun registerCallback(cb: ISagerNetServiceCallback, id: Int) {
            if (id == SagerConnection.CONNECTION_ID_RESTART_BG) {
                Runtime.getRuntime().exit(0)
                return
            }
            if (!callbackIdMap.containsKey(cb.asBinder())) {
                callbacks.register(cb)
            }
            callbackIdMap[cb.asBinder()] = id
        }

        private val broadcastMutex = Mutex()

        suspend fun broadcast(work: (ISagerNetServiceCallback) -> Unit) {
            broadcastMutex.withLock {
                val count = callbacks.beginBroadcast()
                try {
                    repeat(count) {
                        try {
                            work(callbacks.getBroadcastItem(it))
                        } catch (_: RemoteException) {
                        } catch (_: Exception) {
                        }
                    }
                } finally {
                    callbacks.finishBroadcast()
                }
            }
        }

        override fun unregisterCallback(cb: ISagerNetServiceCallback) {
            callbackIdMap.remove(cb.asBinder())
            callbacks.unregister(cb)
        }

        // binder thread: the service may stop meanwhile, so read the instance once
        override fun urlTest(): Int {
            val box = data?.proxy?.takeIf { it.isInitialized() }?.box ?: error("core not started")
            try {
                return Libcore.urlTest(box, DataStore.connectionTestURL, 3000)
            } catch (e: Exception) {
                error(Protocols.genFriendlyMsg(e.readableMessage))
            }
        }

        fun stateChanged(s: State, msg: String?) = launch {
            val profileName = profileName
            broadcast { it.stateChanged(s.ordinal, profileName, msg) }
        }

        fun missingPlugin(pluginName: String) = launch {
            val profileName = profileName
            broadcast { it.missingPlugin(profileName, pluginName) }
        }

        override fun close() {
            callbacks.kill()
            cancel()
            data = null
        }
    }

    interface Interface {
        val data: Data
        val tag: String
        fun createNotification(profileName: String): ServiceNotification

        fun onBind(intent: Intent): IBinder? =
            if (intent.action == Action.SERVICE) data.binder else null

        fun reload() {
            if (DataStore.selectedProxy == 0L) {
                stopRunner(false, (this as Context).getString(R.string.profile_empty))
                return
            }
            if (canReloadSelector()) {
                val ent = SagerDatabase.proxyDao.getById(DataStore.selectedProxy)
                val tag = data.proxy!!.config.profileTagMap[ent?.id] ?: ""
                if (tag.isNotBlank() && ent != null) {
                    // select from GUI
                    data.proxy!!.box.selectOutbound(tag)
                    // or select from webui
                    // => selector_OnProxySelected
                }
                return
            }
            val s = data.state
            when {
                s == State.Stopped -> startRunner()
                s.canStop -> stopRunner(true)
                else -> Logs.w("Illegal state $s when invoking use")
            }
        }

        fun canReloadSelector(): Boolean {
            // while connecting the config is not built yet (lateinit), and there is no box
            val proxy = data.proxy?.takeIf { it.isInitialized() } ?: return false
            if (proxy.config.selectorGroupId < 0) return false
            val ent = SagerDatabase.proxyDao.getById(DataStore.selectedProxy) ?: return false
            val tmpBox = ProxyInstance(ent)
            tmpBox.buildConfigTmp()
            if (tmpBox.lastSelectorGroupId == data.proxy?.lastSelectorGroupId) {
                return true
            }
            return false
        }

        suspend fun startProcesses() {
            data.proxy!!.launch()
        }

        fun startRunner() {
            this as Context
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(Intent(this, javaClass))
            else startService(Intent(this, javaClass))
        }

        suspend fun killProcesses() {
            onIoDispatcher { data.proxy?.close() }
            wakeLock?.apply {
                release()
                wakeLock = null
            }
            data.upstreamNetwork = null
            data.upstreamLinkProperties = null
            data.upstreamNetworkLost = false
            upstreamInterfaceName = null
            SagerNet.underlyingNetwork = null
            Libcore.updateDefaultInterface("", false)
            data.networkListenerKey?.let { key ->
                runOnDefaultDispatcher {
                    DefaultNetworkListener.stop(key)
                }
            }
            data.networkListenerKey = null
        }

        fun stopRunner(restart: Boolean = false, msg: String? = null) {
            DataStore.baseService = null
            DataStore.vpnService = null

            if (data.state == State.Stopping) {
                // the latest request decides whether the running stop starts again
                data.restartAfterStop = restart
                return
            }
            data.restartAfterStop = restart
            data.notification?.destroy()
            data.notification = null
            this as Service

            data.changeState(State.Stopping)

            runOnMainDispatcher {
                data.connectingJob?.cancelAndJoin() // ensure stop connecting first
                // we use a coroutineScope here to allow clean-up in parallel
                coroutineScope {
                    withContext(NonCancellable) {
                        try { killProcesses() } catch (e: Exception) { Logs.w(e) }
                    }
                    val data = data
                    if (data.closeReceiverRegistered) {
                        unregisterReceiver(data.receiver)
                        data.closeReceiverRegistered = false
                    }
                    data.proxy = null
                }

                // change the state
                data.changeState(State.Stopped, msg)
                // stop the service if nothing has bound to it
                if (data.restartAfterStop) {
                    data.restartAfterStop = false
                    startRunner()
                } else {
                    stopSelf()
                }
            }
        }

        fun persistStats() {
            // TODO NEW save app stats?
        }

        // networks
        var upstreamInterfaceName: String?

        suspend fun preInit() {
            // The listener callback is delivered on the main thread, which is busy starting the
            // core, so seed the current network now; otherwise local DNS uses the VPN itself.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val active = SagerNet.connectivity.activeNetwork
                val caps = active?.let { SagerNet.connectivity.getNetworkCapabilities(it) }
                if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    SagerNet.underlyingNetwork = active
                    upstreamInterfaceName = SagerNet.connectivity.getLinkProperties(active)?.interfaceName
                }
            }
            Libcore.updateDefaultInterface(upstreamInterfaceName ?: "", true)
            val key = Any()
            data.networkListenerKey = key
            DefaultNetworkListener.start(key) { network, link ->
                // a late update for a run that is already stopped
                if (data.networkListenerKey !== key) return@start
                if (network == null) {
                    // keep upstreamNetwork, so that a reconnect is detected as a network change
                    Logs.d("Network lost: $upstreamInterfaceName")
                    data.upstreamNetworkLost = true
                    data.upstreamLinkProperties = null
                    // don't report a network that is gone: the VPN follows the default network
                    // meanwhile, and local DNS fails instead of using a dead network
                    SagerNet.underlyingNetwork = null
                    DataStore.vpnService?.updateUnderlyingNetwork()
                    Libcore.updateDefaultInterface("", true)
                    return@start
                }
                // The network is usable before link properties arrive. Android delivers those
                // separately, and a synchronous getLinkProperties() here may return null.
                SagerNet.underlyingNetwork = network
                DataStore.vpnService?.updateUnderlyingNetwork()
                val oldNetwork = data.upstreamNetwork
                val oldLink = data.upstreamLinkProperties
                val oldName = upstreamInterfaceName
                val wasLost = data.upstreamNetworkLost
                val linkChanged = oldNetwork == network && oldLink != null &&
                    link != null && oldLink != link
                data.upstreamNetwork = network
                data.upstreamLinkProperties = if (oldNetwork != network) link else link ?: oldLink
                data.upstreamNetworkLost = false
                if (link != null) upstreamInterfaceName = link.interfaceName
                else if (oldNetwork != network) upstreamInterfaceName = null
                val keepQuic = DataStore.keepQuicOnNetworkChange &&
                    data.proxy?.usesQuic() == true
                val resetOnChange = DataStore.networkChangeResetConnections && !keepQuic
                // An interface notification makes sing-box reset its outbounds itself. For a
                // same-interface reconnect or DNS/route update, the existing reset path applies.
                // Always notify after a loss so the core wakes from its network pause state.
                val coreReset = Libcore.updateDefaultInterface(
                    upstreamInterfaceName ?: "",
                    oldNetwork == null || wasLost || (oldNetwork != network && resetOnChange),
                )
                // A network can recover with the same identity, or change routes/DNS in place.
                if (oldNetwork != null && (wasLost || oldNetwork != network || linkChanged)) {
                    Logs.d("Network changed: $oldNetwork/$oldName -> $network/$upstreamInterfaceName, link changed: $linkChanged")
                    if (DataStore.networkChangeResetConnections) {
                        if (keepQuic && !wasLost) {
                            // QUIC migrates to the new network by itself; a reset would close it
                            Logs.d("Network changed, keep connections of QUIC proxy")
                        } else if (!coreReset) {
                            data.resetConnections("Network changed", true)
                        }
                    }
                }
            }
            if (!DefaultNetworkListener.listening) {
                // the listener retries; until then a network change does not reset connections
                Logs.w("Network changes are not monitored, connections are not reset on network change")
            }
        }

        var wakeLock: PowerManager.WakeLock?
        fun acquireWakeLock()

        suspend fun lateInit() {
            wakeLock?.apply {
                release()
                wakeLock = null
            }

            if (DataStore.acquireWakeLock) {
                acquireWakeLock()
                data.notification?.postNotificationWakeLockStatus(true)
            } else {
                data.notification?.postNotificationWakeLockStatus(false)
            }
        }

        fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
            DataStore.baseService = this

            val data = data
            if (data.state == State.Stopping) {
                // Not in the foreground any more, and a start from startForegroundService must
                // reach startForeground: start again once stopped, which creates the notification.
                data.restartAfterStop = true
                return Service.START_NOT_STICKY
            }
            if (data.state != State.Stopped) return Service.START_NOT_STICKY
            val profile = SagerDatabase.proxyDao.getById(DataStore.selectedProxy)
            this as Context
            if (profile == null) { // gracefully shutdown: https://stackoverflow.com/q/47337857/2245107
                runOnMainDispatcher {
                    try {
                        data.notification = createNotification("")
                        data.notification!!.start()
                    } catch (e: Exception) { Logs.w(e) }
                    finally { stopRunner(false, getString(R.string.profile_empty)) }
                }
                return Service.START_NOT_STICKY
            }

            val proxy = ProxyInstance(profile, this)
            data.proxy = proxy
            BootReceiver.enabled = DataStore.persistAcrossReboot
            if (!data.closeReceiverRegistered) {
                val filter = IntentFilter().apply {
                    addAction(Action.RELOAD)
                    addAction(Intent.ACTION_SHUTDOWN)
                    addAction(Action.CLOSE)
                    // addAction(Action.SWITCH_WAKE_LOCK)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                    }
                    addAction(Action.RESET_UPSTREAM_CONNECTIONS)
                    addAction(Intent.ACTION_SCREEN_ON)
                    addAction(Intent.ACTION_SCREEN_OFF)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(
                        data.receiver,
                        filter,
                        "$packageName.SERVICE",
                        null,
                        Context.RECEIVER_EXPORTED
                    )
                } else {
                    registerReceiver(
                        data.receiver,
                        filter,
                        "$packageName.SERVICE",
                        null
                    )
                }
                data.closeReceiverRegistered = true
            }

            data.changeState(State.Connecting)
            data.connectingJob = runOnMainDispatcher {
                try {
                    data.notification = createNotification(ServiceNotification.genTitle(profile))
                    data.notification!!.start()

                    Executable.killAll()    // clean up old processes
                    preInit()
                    proxy.init()
                    DataStore.currentProfile = profile.id

                    proxy.processes = GuardedProcessPool {
                        Logs.w(it)
                        // posted to the main thread: by then this run may be stopped and a new one
                        // started, which a late failure of an old plugin must not stop
                        if (data.proxy === proxy) stopRunner(false, it.readableMessage)
                    }

                    startProcesses()
                    data.changeState(State.Connected)

                    lateInit()
                } catch (_: CancellationException) { // if the job was cancelled, it is canceller's responsibility to call stopRunner
                } catch (_: UnknownHostException) {
                    stopRunner(false, getString(R.string.invalid_server))
                } catch (e: PluginManager.PluginNotFoundException) {
                    Toast.makeText(this@Interface, e.readableMessage, Toast.LENGTH_SHORT).show()
                    Logs.w(e)
                    data.binder.missingPlugin(e.plugin)
                    stopRunner(false, null)
                } catch (exc: Throwable) {
                    if (exc.javaClass.name.endsWith("proxyerror")) {
                        // error from golang
                        Logs.w(exc.readableMessage)
                    } else {
                        Logs.w(exc)
                    }
                    stopRunner(
                        false, "${getString(R.string.service_failed)}: ${exc.readableMessage}"
                    )
                } finally {
                    data.connectingJob = null
                }
            }
            return Service.START_NOT_STICKY
        }
    }

}
