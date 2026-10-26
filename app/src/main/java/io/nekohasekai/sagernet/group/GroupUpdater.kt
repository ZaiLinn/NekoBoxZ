package io.nekohasekai.sagernet.group

import io.nekohasekai.sagernet.*
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.GroupManager
import io.nekohasekai.sagernet.database.ProxyGroup
import io.nekohasekai.sagernet.database.SubscriptionBean
import io.nekohasekai.sagernet.fmt.AbstractBean
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.isTLS
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import moe.matsuri.nb4a.proxy.anytls.AnyTLSBean
import io.nekohasekai.sagernet.utils.selectResolvedAddress
import kotlinx.coroutines.*
import java.net.Inet4Address
import java.net.InetAddress
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

@Suppress("EXPERIMENTAL_API_USAGE")
abstract class GroupUpdater {

    abstract suspend fun doUpdate(
        proxyGroup: ProxyGroup,
        subscription: SubscriptionBean,
        userInterface: GroupManager.Interface?,
        byUser: Boolean
    )

    data class Progress(
        var max: Int
    ) {
        var progress by AtomicInteger()
    }

    protected suspend fun forceResolve(
        profiles: List<AbstractBean>, groupId: Long?
    ) {
        val ipv6Mode = DataStore.ipv6Mode
        val lookupPool = newFixedThreadPoolContext(5, "DNS Lookup")
        val lookupJobs = mutableListOf<Job>()
        val progress = Progress(profiles.size)
        if (groupId != null) {
            GroupUpdater.progress[groupId] = progress
            GroupManager.postReload(groupId)
        }

        // the pool's 5 threads stay alive until it is closed, also when the update is cancelled
        try {
            for (profile in profiles) {
                when (profile) {
                    // SNI rewrite unsupported
                    is NaiveBean -> continue
                }

                if (profile.serverAddress.isIpAddress()) continue

                lookupJobs.add(GlobalScope.launch(lookupPool) {
                    try {
                        val results = if (
                            SagerNet.underlyingNetwork != null &&
                            DataStore.enableFakeDns &&
                            DataStore.serviceState.started &&
                            DataStore.serviceMode == Key.MODE_VPN
                        ) {
                            // FakeDNS
                            SagerNet.underlyingNetwork!!
                                .getAllByName(profile.serverAddress)
                                .filterNotNull()
                        } else {
                            // System DNS is enough (when VPN connected, it uses v2ray-core)
                            InetAddress.getAllByName(profile.serverAddress).filterNotNull()
                        }
                        if (results.isEmpty()) error("empty response")
                        rewriteAddress(profile, results, ipv6Mode)
                    } catch (e: Exception) {
                        Logs.d("Lookup ${profile.serverAddress} failed: ${e.readableMessage}", e)
                    }
                    if (groupId != null) {
                        progress.progress++
                        GroupManager.postReload(groupId)
                    }
                })
            }

            lookupJobs.joinAll()
        } finally {
            lookupJobs.forEach { it.cancel() }
            lookupPool.close()
        }
    }

    protected fun rewriteAddress(
        bean: AbstractBean, addresses: List<InetAddress>, ipv6Mode: Int
    ) {
        val address = selectResolvedAddress(addresses, ipv6Mode).hostAddress

        with(bean) {
            when (this) {
                is HttpBean -> {
                    if (isTLS() && sni.isBlank()) sni = bean.serverAddress
                }
                is StandardV2RayBean -> {
                    when (security) {
                        "tls" -> if (sni.isBlank()) sni = bean.serverAddress
                    }
                }
                is TrojanBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
                is TrojanGoBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
                is HysteriaBean -> {
                    if (sni.isBlank()) sni = bean.serverAddress
                }
                is TuicBean -> if (sni.isBlank()) sni = bean.serverAddress
                is AnyTLSBean -> if (sni.isBlank()) sni = bean.serverAddress
            }

            bean.serverAddress = address
        }
    }

    companion object {

        val updating = Collections.synchronizedSet<Long>(mutableSetOf())
        val progress = Collections.synchronizedMap<Long, Progress>(mutableMapOf())

        fun startUpdate(proxyGroup: ProxyGroup, byUser: Boolean) {
            runOnDefaultDispatcher {
                executeUpdate(proxyGroup, byUser)
            }
        }

        suspend fun executeUpdate(proxyGroup: ProxyGroup, byUser: Boolean): Boolean {
            if (!updating.add(proxyGroup.id)) return false
            try {
                GroupManager.postReload(proxyGroup.id)

                val subscription = proxyGroup.subscription!!
                val connected = DataStore.serviceState.connected
                val userInterface = GroupManager.userInterface

                if (byUser && (subscription.link?.startsWith("http://") == true || subscription.updateWhenConnectedOnly) && !connected) {
                    if (userInterface == null || !userInterface.confirm(app.getString(R.string.update_subscription_warning))) {
                        return false
                    }
                }

                RawUpdater.doUpdate(proxyGroup, subscription, userInterface, byUser)
                return true
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Logs.w("Subscription update failed (${e.javaClass.simpleName})")
                GroupManager.userInterface?.onUpdateFailure(proxyGroup, e.readableMessage)
                return false
            } finally {
                // Clear the guard even when loading the subscription, a confirmation dialog,
                // or an update callback fails or is cancelled.
                updating.remove(proxyGroup.id)
                progress.remove(proxyGroup.id)
                withContext(NonCancellable) { GroupManager.postUpdate(proxyGroup) }
            }
        }

    }

}
