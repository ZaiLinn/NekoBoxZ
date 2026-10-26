package io.nekohasekai.sagernet.bg.proto

import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.aidl.SpeedDisplayData
import io.nekohasekai.sagernet.aidl.TrafficData
import io.nekohasekai.sagernet.bg.BaseService
import io.nekohasekai.sagernet.bg.SagerConnection
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProfileManager
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.fmt.TAG_BYPASS
import io.nekohasekai.sagernet.fmt.TAG_PROXY
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.runOnDefaultDispatcher
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class TrafficLooper
    (
    val data: BaseService.Data, private val sc: CoroutineScope
) {

    private var job: Job? = null
    private var trafficUpdater: TrafficUpdater? = null
    private val idMap = mutableMapOf<Long, TrafficUpdater.TrafficLooperData>() // id to 1 data
    private val tagMap = mutableMapOf<String, TrafficUpdater.TrafficLooperData>() // tag to 1 data
    private val saveLock = Mutex()
    private val stateLock = Mutex()
    @Volatile private var stopped = false
    private val savedTraffic = mutableMapOf<Long, Pair<Long, Long>>()

    private suspend fun saveTraffic(id: Long, item: TrafficUpdater.TrafficLooperData) = saveLock.withLock {
        val rxNow = item.rx
        val txNow = item.tx
        val previous = savedTraffic[id] ?: (item.rxBase to item.txBase)
        val rx = (rxNow - previous.first).coerceAtLeast(0)
        val tx = (txNow - previous.second).coerceAtLeast(0)
        if (SagerDatabase.proxyDao.addTraffic(id, rx, tx) == 0) return@withLock
        savedTraffic[id] = rxNow to txNow
        val current = SagerDatabase.proxyDao.getById(id) ?: return@withLock
        ProfileManager.postUpdate(TrafficData(id = id, rx = current.rx, tx = current.tx))
    }

    suspend fun stop() {
        stopped = true
        job?.cancelAndJoin()
        stateLock.withLock {
            // finally traffic post
            if (!DataStore.profileTrafficStatistics) return
            // collect traffic since the last update (including while polling was paused)
            runCatching { trafficUpdater?.updateAll() }
            val traffic = mutableMapOf<Long, TrafficData>()
            data.proxy?.config?.trafficMap?.forEach { (_, ents) ->
                for (ent in ents) {
                    val item = idMap[ent.id] ?: return@forEach
                    saveTraffic(ent.id, item)
                    val current = SagerDatabase.proxyDao.getById(ent.id) ?: continue
                    traffic[ent.id] = TrafficData(
                        id = ent.id,
                        rx = current.rx,
                        tx = current.tx,
                    )
                }
            }
            data.binder.broadcast { b ->
                for (t in traffic) {
                    b.cbTrafficUpdate(t.value)
                }
            }
            Logs.d("finally traffic post done")
        }
    }

    fun start() {
        job = sc.launch { loop() }
    }

    var selectorNowId = -114514L
    var selectorNowFakeTag = ""

    suspend fun selectMain(id: Long) = stateLock.withLock {
        if (stopped) return@withLock
        Logs.d("select traffic count $TAG_PROXY to $id, old id is $selectorNowId")
        val oldData = idMap[selectorNowId]
        val newData = idMap[id] ?: return@withLock
        oldData?.apply {
            tag = selectorNowFakeTag
            ignore = true
            // post traffic when switch
            if (DataStore.profileTrafficStatistics) {
                data.proxy?.config?.trafficMap?.get(tag)?.firstOrNull()?.let {
                    saveTraffic(it.id, this@apply)
                }
            }
        }
        selectorNowFakeTag = newData.tag
        selectorNowId = id
        newData.apply {
            tag = TAG_PROXY
            ignore = false
        }
    }

    private suspend fun loop() {
        val delayMs = DataStore.speedInterval.toLong()
        val showDirectSpeed = DataStore.showDirectSpeed
        val profileTrafficStatistics = DataStore.profileTrafficStatistics
        if (delayMs == 0L) return

        var proxy: ProxyInstance?

        // for display
        val itemBypass = TrafficUpdater.TrafficLooperData(tag = TAG_BYPASS)

        while (sc.isActive) {
            proxy = data.proxy
            if (proxy == null) {
                delay(delayMs)
                continue
            }

            // Nobody can see the speed while the screen is off, so skip polling to save battery.
            // Stats counters are reset on read, so the traffic is still counted on the next update.
            if (trafficUpdater != null && !SagerNet.power.isInteractive) {
                delay(delayMs)
                continue
            }

            var trafficUpdater = trafficUpdater
            if (trafficUpdater == null) {
                if (!proxy.isInitialized()) {
                    delay(delayMs)
                    continue
                }
                idMap.clear()
                idMap[-1] = itemBypass
                //
                val tags = hashSetOf(TAG_PROXY, TAG_BYPASS)
                proxy.config.trafficMap.forEach { (tag, ents) ->
                    tags.add(tag)
                    for (ent in ents) {
                        val item = TrafficUpdater.TrafficLooperData(
                            tag = tag,
                            rx = ent.rx,
                            tx = ent.tx,
                            rxBase = ent.rx,
                            txBase = ent.tx,
                            ignore = proxy.config.selectorGroupId >= 0L,
                        )
                        idMap[ent.id] = item
                        tagMap[tag] = item
                        Logs.d("traffic count $tag to ${ent.id}")
                    }
                }
                if (proxy.config.selectorGroupId >= 0L) {
                    selectMain(proxy.config.mainEntId)
                }
                //
                trafficUpdater = TrafficUpdater(
                    box = proxy.box, items = idMap.values.toList()
                )
                this.trafficUpdater = trafficUpdater
                proxy.box.setV2rayStats(tags.joinToString("\n"))
            }

            trafficUpdater.updateAll()
            if (!sc.isActive) return

            // add all non-bypass to "main"
            var mainTxRate = 0L
            var mainRxRate = 0L
            var mainTx = 0L
            var mainRx = 0L
            tagMap.forEach { (_, it) ->
                if (!it.ignore) {
                    mainTxRate += it.txRate
                    mainRxRate += it.rxRate
                }
                mainTx += it.tx - it.txBase
                mainRx += it.rx - it.rxBase
            }

            // speed
            val speed = SpeedDisplayData(
                mainTxRate,
                mainRxRate,
                if (showDirectSpeed) itemBypass.txRate else 0L,
                if (showDirectSpeed) itemBypass.rxRate else 0L,
                mainTx,
                mainRx
            )

            // broadcast (MainActivity)
            if (data.state == BaseService.State.Connected
                && data.binder.callbackIdMap.containsValue(SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_FOREGROUND)
            ) {
                data.binder.broadcast { b ->
                    if (data.binder.callbackIdMap[b.asBinder()] == SagerConnection.CONNECTION_ID_MAIN_ACTIVITY_FOREGROUND) {
                        b.cbSpeedUpdate(speed)
                        if (profileTrafficStatistics) {
                            idMap.forEach { (id, item) ->
                                b.cbTrafficUpdate(
                                    TrafficData(id = id, rx = item.rx, tx = item.tx) // display
                                )
                            }
                        }
                    }
                }
            }

            // ServiceNotification
            data.notification?.apply {
                if (listenPostSpeed) postNotificationSpeedUpdate(speed)
            }

            delay(delayMs)
        }
    }
}
