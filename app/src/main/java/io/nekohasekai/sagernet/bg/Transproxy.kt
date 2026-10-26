package io.nekohasekai.sagernet.bg

import android.os.Process
import io.nekohasekai.sagernet.IPv6Mode
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.LOCALHOST
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.app
import io.nekohasekai.sagernet.utils.PackageCache
import java.io.File
import java.io.IOException

/**
 * Root transparent proxy, adapted from v2rayNG's root mode (RootProxyManager).
 *
 * The core runs inside the app without root, so it can neither create a tun device nor use
 * TPROXY. Instead a bundled hev-socks5-tunnel executable is started as root: it creates a tun
 * device and forwards everything (TCP and UDP) to the core's mixed (SOCKS5) inbound. Traffic of
 * the selected apps is marked in iptables mangle OUTPUT and policy routed into that tun.
 *
 * All rules live in dedicated chains plus a dedicated routing table, so cleanup is a bounded
 * flush. Cleanup runs before every setup (stale rules) and on every stop, because rules left
 * behind after the core died would break the device's network.
 */
object Transproxy {

    private const val BIN = "libhevsockstun.so"
    private const val TUN = "nbz_tun"
    private const val TUN_ADDR_V4 = "198.18.0.1/15"
    private const val TUN_ADDR_V6 = "fdfe:dcba:9876::1/64"
    private const val TABLE = 2096
    private const val PRIORITY = 1000
    private const val MARK = 0x2096

    private const val CHAIN = "NBZ_MARK"
    private const val CHAIN_V6_REJECT = "NBZ6_REJECT"
    private const val CHAIN_FWD = "NBZ_FWD"
    private const val CHAIN_FWD_DNS = "NBZ_FWD_DNS"
    private const val CHAIN_V6_FWD = "NBZ6_FWD"
    private const val CHAIN_V6_PRE = "NBZ6_PRE"

    // keeps the low memory killer away from the core while the whole device depends on it
    private const val OOM_SCORE = "-1000"
    private const val SU_TIMEOUT_MS = 30_000L

    // fallback DNS for hotspot clients when the remote DNS is not a plain IPv4 address
    private const val LAN_DNS = "1.1.1.1"

    private val BYPASS_V4 = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    )
    private val BYPASS_V6 = listOf("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")

    private val runDir get() = File(app.noBackupFilesDir, "transproxy").apply { mkdirs() }

    // exists while rules may be installed, so leftovers (e.g. after a crash) get removed
    private val flagFile get() = File(runDir, "active")

    class RootException(message: String) : IOException(message), BaseService.ExpectedException

    @Volatile private var generation = ""
    private fun activeToken() = runCatching { flagFile.readText() }.getOrDefault("")
    fun tunnelFailed() = File(runDir, "failed-$generation").exists()

    private fun scriptLock() = buildString {
        appendLine("exec 9>'${runDir.absolutePath}/rules.lock'")
        appendLine("i=0; until flock -n 9; do i=\$((i+1)); [ \$i -lt 100 ] || exit 1; sleep 0.1; done")
    }

    @Synchronized
    fun start() {
        val bin = File(app.applicationInfo.nativeLibraryDir, BIN)
        if (!bin.exists()) throw RootException(app.getString(R.string.transproxy_failed, "$BIN not found"))
        cleanup()
        generation = java.util.UUID.randomUUID().toString()
        flagFile.writeText(generation)
        File(runDir, "hev.yml").writeText(hevConfig())
        // run by the root watchdog when the core dies without a cleanup (crash, force stop)
        File(runDir, "cleanup-$generation.sh").writeText(xtablesWait(cleanupScript(byWatchdog = true)))
        try {
            runSu(setupScript(bin))
        } catch (e: Exception) {
            try { cleanup() } catch (failure: Exception) { e.addSuppressed(failure) }
            throw e
        }
        Logs.i("transproxy: started")
    }

    @Synchronized
    fun cleanup() {
        if (!flagFile.exists()) return
        try {
            runSu(cleanupScript())
            flagFile.delete()
            Logs.i("transproxy: rules removed")
        } catch (e: Exception) {
            Logs.w(e)
            throw e // preserve the active marker until cleanup is verified
        }
    }

    private val ipv6 get() = DataStore.ipv6Mode != IPv6Mode.DISABLE

    private fun hevConfig() = buildString {
        appendLine("tunnel:")
        appendLine("  name: '$TUN'")
        appendLine("  mtu: ${DataStore.mtu}")
        appendLine("  multi-queue: true")
        appendLine("  ipv4: '${TUN_ADDR_V4.substringBefore("/")}'")
        if (ipv6) appendLine("  ipv6: '${TUN_ADDR_V6.substringBefore("/")}'")
        appendLine("socks5:")
        appendLine("  port: ${DataStore.mixedPort}")
        appendLine("  address: '$LOCALHOST'")
        appendLine("  udp: 'udp'")
    }

    private fun setupScript(bin: File): String = buildString {
        val dir = runDir.absolutePath
        val corePid = Process.myPid()
        appendLine("set -e")
        append(scriptLock())
        appendLine("iptables -t mangle -S >/dev/null")
        appendLine("ip6tables -t filter -S >/dev/null")
        if (ipv6) appendLine("ip6tables -t mangle -S >/dev/null")
        appendLine("[ -z \"\$(ip route show table $TABLE 2>/dev/null)\" ] || { echo 'routing table already in use'; exit 1; }")
        appendLine("[ -z \"\$(ip rule show | grep -E '^[[:space:]]*$PRIORITY:')\" ] || { echo 'routing priority already in use'; exit 1; }")
        appendLine("touch '$dir/owned'")
        appendLine("SETUP_OK=0; trap 'flock -u 9; exec 9>&-; [ \"\$SETUP_OK\" = 1 ] || sh \"$dir/cleanup-${activeToken()}.sh\"' EXIT")
        appendLine("CORE_START=\$(cut -d' ' -f22 /proc/$corePid/stat)")
        appendLine("mkdir -p '$dir/sysctl'")
        appendLine("cat /proc/sys/net/ipv4/conf/all/rp_filter > '$dir/sysctl/rp_filter'")
        if (DataStore.rootLanSharing) appendLine("cat /proc/sys/net/ipv4/ip_forward > '$dir/sysctl/ip_forward'")
        appendLine("if [ ! -e /dev/net/tun ]; then mkdir -p /dev/net; mknod /dev/net/tun c 10 200; chmod 666 /dev/net/tun; fi")
        appendLine("nohup '${bin.absolutePath}' '$dir/hev.yml' >'$dir/hev.log' 2>&1 9>&- &")
        appendLine("HEV_PID=\$!")
        appendLine("echo \$HEV_PID > '$dir/hev.pid'")
        appendLine("cut -d' ' -f22 /proc/\$HEV_PID/stat > '$dir/hev.start'")
        appendLine("echo $OOM_SCORE > /proc/\$HEV_PID/oom_score_adj 2>/dev/null || true")
        appendLine("i=0; while [ \$i -lt 20 ]; do ip link show $TUN >/dev/null 2>&1 && break; sleep 0.3; i=\$((i+1)); done")
        appendLine("ip link show $TUN >/dev/null 2>&1 || { echo 'tun device did not come up'; cat '$dir/hev.log'; exit 1; }")
        appendLine("echo 0 > /proc/sys/net/ipv4/conf/$TUN/rp_filter 2>/dev/null || true")
        appendLine("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true")
        appendLine("ip addr add $TUN_ADDR_V4 dev $TUN 2>/dev/null || true")
        appendLine("ip link set dev $TUN up")
        appendLine("ip route replace default dev $TUN table $TABLE")
        appendLine("ip rule add fwmark $MARK table $TABLE priority $PRIORITY")
        append(markRules("iptables", BYPASS_V4))
        if (DataStore.rootLanSharing) append(lanSharingRules())
        // The advertised IPv6 capture/block policy is mandatory, not best effort.
        if (ipv6) {
            appendLine("ip -6 addr add $TUN_ADDR_V6 dev $TUN 2>/dev/null")
            appendLine("ip -6 route replace default dev $TUN table $TABLE 2>/dev/null")
            appendLine("ip -6 rule add fwmark $MARK table $TABLE priority $PRIORITY")
            append(markRules("ip6tables", BYPASS_V6))
        } else {
            append(v6RejectRules())
        }
        // Supervise both processes. The root watcher can restore networking even if Java dies.
        appendLine("nohup sh -c 'while [ \"\$(cut -d\" \" -f22 /proc/$corePid/stat 2>/dev/null)\" = \"'\$CORE_START'\" ] && [ \"\$(cut -d\" \" -f22 /proc/'\$HEV_PID'/stat 2>/dev/null)\" = \"\$(cat \"$dir/hev.start\" 2>/dev/null)\" ]; do echo $OOM_SCORE > /proc/$corePid/oom_score_adj 2>/dev/null; sleep 2; done; touch \"$dir/failed-${activeToken()}\"; while ! sh \"$dir/cleanup-${activeToken()}.sh\"; do sleep 2; done' >/dev/null 2>&1 9>&- &")
        appendLine("echo \$! > '$dir/oomguard.pid'")
        appendLine("cut -d' ' -f22 /proc/\$!/stat > '$dir/oomguard.start'")
        appendLine("SETUP_OK=1")
        appendLine("exit 0")
    }

    /**
     * mangle OUTPUT marking, mirroring what the VPN mode captures:
     * all apps / bypass mode mark every remaining uid, proxy mode only the selected apps.
     */
    private fun markRules(cmd: String, bypass: List<String>): String {
        val (proxyOnly, uids) = selectedApps()
        return markRules(cmd, bypass, Process.myUid(), proxyOnly, uids)
    }

    internal fun markRules(
        cmd: String, bypass: List<String>, coreUid: Int, proxyOnly: Boolean, uids: Set<Int>,
    ) = buildString {
        val mangle = "$cmd -t mangle"
        appendLine("$mangle -N $CHAIN")
        // never touch the core's own (outbound) connections, or they would loop into the tun
        appendLine("$mangle -A $CHAIN -m owner --uid-owner $coreUid -j RETURN")
        if (!proxyOnly) for (uid in uids) appendLine("$mangle -A $CHAIN -m owner --uid-owner $uid -j RETURN")
        // DNS before the LAN bypass, so queries to the router are resolved by the core too;
        // in proxy-only mode only the selected apps' DNS, like the VPN mode
        val owners = if (proxyOnly) uids.map { "-m owner --uid-owner $it " } else listOf("")
        for (owner in owners) {
            appendLine("$mangle -A $CHAIN ${owner}-p udp --dport 53 -j MARK --set-xmark $MARK")
            appendLine("$mangle -A $CHAIN ${owner}-p tcp --dport 53 -j MARK --set-xmark $MARK")
        }
        for (cidr in bypass) appendLine("$mangle -A $CHAIN -d $cidr -j RETURN")
        if (proxyOnly) {
            for (uid in uids) appendLine("$mangle -A $CHAIN -m owner --uid-owner $uid -j MARK --set-xmark $MARK")
        } else {
            appendLine("$mangle -A $CHAIN -j MARK --set-xmark $MARK")
        }
        appendLine("$mangle -A OUTPUT -j $CHAIN")
    }

    /**
     * Adds -w to every iptables / ip6tables call: netd holds the xtables lock often, and without
     * waiting a call fails at once, which under `set -e` fails the whole setup.
     */
    internal fun xtablesWait(script: String) =
        script.replace(Regex("(?<![\\w-])(ip6?tables)(?= )"), "$1 -w 5")

    /** IPv6 disabled: reject captured apps' native IPv6 so they fall back to IPv4 instead of leaking. */
    private fun v6RejectRules() = buildString {
        val filter = "ip6tables -t filter"
        val reject = "-j REJECT --reject-with icmp6-adm-prohibited"
        appendLine("$filter -N $CHAIN_V6_REJECT")
        appendLine("$filter -A $CHAIN_V6_REJECT -m owner --uid-owner ${Process.myUid()} -j RETURN")
        appendLine("$filter -A $CHAIN_V6_REJECT -o lo -j RETURN")
        for (cidr in BYPASS_V6) appendLine("$filter -A $CHAIN_V6_REJECT -d $cidr -j RETURN")
        val (proxyOnly, uids) = selectedApps()
        if (proxyOnly) {
            for (uid in uids) appendLine("$filter -A $CHAIN_V6_REJECT -m owner --uid-owner $uid $reject")
        } else {
            for (uid in uids) appendLine("$filter -A $CHAIN_V6_REJECT -m owner --uid-owner $uid -j RETURN")
            appendLine("$filter -A $CHAIN_V6_REJECT $reject")
        }
        appendLine("$filter -A OUTPUT -j $CHAIN_V6_REJECT")
    }

    /** Route Wi-Fi hotspot / USB tethering clients through the tun as well. */
    private fun lanSharingRules() = buildString {
        val dns = DataStore.remoteDns.lines().map { it.trim() }
            .firstOrNull { it.matches(Regex("\\d{1,3}(\\.\\d{1,3}){3}")) } ?: LAN_DNS
        appendLine("echo 1 > /proc/sys/net/ipv4/ip_forward")
        appendLine("iptables -N $CHAIN_FWD")
        appendLine("iptables -A $CHAIN_FWD -i $TUN -j ACCEPT")
        appendLine("iptables -A $CHAIN_FWD -o $TUN -j ACCEPT")
        appendLine("iptables -I FORWARD -j $CHAIN_FWD")
        appendLine("iptables -t mangle -A FORWARD -o $TUN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350")
        // clients' DNS to the hotspot / LAN goes to a public resolver, i.e. through the tun
        appendLine("iptables -t nat -N $CHAIN_FWD_DNS")
        for (cidr in listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")) {
            appendLine("iptables -t nat -A $CHAIN_FWD_DNS ! -i $TUN -d $cidr -p udp --dport 53 -j DNAT --to $dns")
        }
        appendLine("iptables -t nat -A PREROUTING -j $CHAIN_FWD_DNS")
        // policy routing: replies via main, LAN direct, forwarded clients via the tun table
        for (rule in lanPolicyRules()) {
            val pref = rule.substringAfterLast("pref ")
            appendLine("[ -z \"\$(ip rule show | grep -E '^[[:space:]]*$pref:')\" ] || { echo 'LAN routing priority already in use'; exit 1; }")
        }
        appendLine("touch '${runDir.absolutePath}/lan.active'")
        for (rule in lanPolicyRules()) appendLine("ip rule add $rule")
        // clients' native IPv6 would bypass the proxy: tunnel it, or reject when IPv6 is off
        appendLine("ip6tables -N $CHAIN_V6_FWD")
        appendLine("ip6tables -I FORWARD -j $CHAIN_V6_FWD")
        if (ipv6) {
            appendLine("ip6tables -A $CHAIN_V6_FWD -i $TUN -j ACCEPT")
            appendLine("ip6tables -A $CHAIN_V6_FWD -o $TUN -j ACCEPT")
            appendLine("ip6tables -t mangle -N $CHAIN_V6_PRE")
            appendLine("ip6tables -t mangle -A $CHAIN_V6_PRE ! -i $TUN -p udp --dport 53 -j MARK --set-xmark $MARK")
            appendLine("ip6tables -t mangle -A $CHAIN_V6_PRE ! -i $TUN -p tcp --dport 53 -j MARK --set-xmark $MARK")
            for (cidr in BYPASS_V6) appendLine("ip6tables -t mangle -A $CHAIN_V6_PRE ! -i $TUN -d $cidr -j RETURN")
            appendLine("ip6tables -t mangle -A $CHAIN_V6_PRE ! -i $TUN -j MARK --set-xmark $MARK")
            appendLine("ip6tables -t mangle -A PREROUTING -j $CHAIN_V6_PRE")
        }
        appendLine("ip6tables -A $CHAIN_V6_FWD -j REJECT --reject-with icmp6-no-route")
    }

    internal fun lanPolicyRules() = listOf(
        "iif lo goto 6000 pref 5000", "iif $TUN lookup main suppress_prefixlength 0 pref 5010",
        "iif $TUN goto 6000 pref 5020", "to 10.0.0.0/8 lookup main pref 5025",
        "to 172.16.0.0/12 lookup main pref 5026", "to 192.168.0.0/16 lookup main pref 5027",
        "from 10.0.0.0/8 lookup $TABLE pref 5030", "from 172.16.0.0/12 lookup $TABLE pref 5040",
        "from 192.168.0.0/16 lookup $TABLE pref 5050", "nop pref 6000",
    )

    /** @return (proxy only the selected apps, selected uids) */
    private fun selectedApps(): Pair<Boolean, Set<Int>> {
        if (!DataStore.proxyApps) return false to emptySet()
        PackageCache.awaitLoadSync()
        val uids = DataStore.individual.split('\n').filter { it.isNotBlank() }
            .mapNotNull { PackageCache[it] }.toSortedSet()
        return !DataStore.bypass to uids
    }

    /** @param byWatchdog run by the watchdog after the core died: its pid may be reused already */
    private fun cleanupScript(byWatchdog: Boolean = false) = buildString {
        val dir = runDir.absolutePath
        append(scriptLock())
        appendLine("[ \"\$(cat '$dir/active' 2>/dev/null)\" = '${activeToken()}' ] || exit 0")
        appendLine("[ -f '$dir/owned' ] || exit 0")
        appendLine("CLEANUP_OK=1")
        appendLine("iptables -t mangle -S >/dev/null || CLEANUP_OK=0")
        appendLine("ip6tables -t filter -S >/dev/null || CLEANUP_OK=0")
        for (cmd in listOf("iptables", "ip6tables")) {
            appendLine("while $cmd -t mangle -D OUTPUT -j $CHAIN 2>/dev/null; do :; done")
            appendLine("$cmd -t mangle -F $CHAIN 2>/dev/null; $cmd -t mangle -X $CHAIN 2>/dev/null")
        }
        appendLine("while ip6tables -D OUTPUT -j $CHAIN_V6_REJECT 2>/dev/null; do :; done")
        appendLine("ip6tables -F $CHAIN_V6_REJECT 2>/dev/null; ip6tables -X $CHAIN_V6_REJECT 2>/dev/null")
        appendLine("while ip rule del fwmark $MARK table $TABLE 2>/dev/null; do :; done")
        appendLine("while ip -6 rule del fwmark $MARK table $TABLE 2>/dev/null; do :; done")
        appendLine("ip route del default dev $TUN table $TABLE 2>/dev/null; ip -6 route del default dev $TUN table $TABLE 2>/dev/null")
        // LAN sharing (harmless if it was never set up)
        appendLine("while iptables -D FORWARD -j $CHAIN_FWD 2>/dev/null; do :; done")
        appendLine("iptables -F $CHAIN_FWD 2>/dev/null; iptables -X $CHAIN_FWD 2>/dev/null")
        appendLine("while iptables -t mangle -D FORWARD -o $TUN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null; do :; done")
        appendLine("while iptables -t nat -D PREROUTING -j $CHAIN_FWD_DNS 2>/dev/null; do :; done")
        appendLine("iptables -t nat -F $CHAIN_FWD_DNS 2>/dev/null; iptables -t nat -X $CHAIN_FWD_DNS 2>/dev/null")
        appendLine("while ip6tables -D FORWARD -j $CHAIN_V6_FWD 2>/dev/null; do :; done")
        appendLine("ip6tables -F $CHAIN_V6_FWD 2>/dev/null; ip6tables -X $CHAIN_V6_FWD 2>/dev/null")
        appendLine("while ip6tables -t mangle -D PREROUTING -j $CHAIN_V6_PRE 2>/dev/null; do :; done")
        appendLine("ip6tables -t mangle -F $CHAIN_V6_PRE 2>/dev/null; ip6tables -t mangle -X $CHAIN_V6_PRE 2>/dev/null")
        appendLine("if [ -f '$dir/lan.active' ]; then")
        for (rule in lanPolicyRules()) {
            appendLine("ip rule del $rule 2>/dev/null || true")
        }
        appendLine("rm -f '$dir/lan.active'")
        appendLine("fi")
        // Restore only settings whose current value is still the value this run installed.
        appendLine("if [ -f '$dir/sysctl/rp_filter' ]; then if [ \"\$(cat /proc/sys/net/ipv4/conf/all/rp_filter)\" = 0 ]; then cat '$dir/sysctl/rp_filter' > /proc/sys/net/ipv4/conf/all/rp_filter || exit 1; fi; rm '$dir/sysctl/rp_filter'; fi")
        appendLine("if [ -f '$dir/sysctl/ip_forward' ]; then if [ \"\$(cat /proc/sys/net/ipv4/ip_forward)\" = 1 ]; then cat '$dir/sysctl/ip_forward' > /proc/sys/net/ipv4/ip_forward || exit 1; fi; rm '$dir/sysctl/ip_forward'; fi")
        // tun device, hev and the LMK guard
        appendLine("ip link set dev $TUN down 2>/dev/null")
        appendLine("if [ -f '$dir/hev.pid' ] && [ -f '$dir/hev.start' ]; then PID=\$(cat '$dir/hev.pid'); if [ \"\$(cut -d' ' -f22 /proc/\$PID/stat 2>/dev/null)\" = \"\$(cat '$dir/hev.start')\" ]; then kill \$PID 2>/dev/null; fi; fi; rm -f '$dir/hev.pid' '$dir/hev.start'")
        for ((cmd, table, chain) in listOf(
            Triple("iptables", "mangle", CHAIN), Triple("ip6tables", "mangle", CHAIN),
            Triple("ip6tables", "filter", CHAIN_V6_REJECT), Triple("iptables", "filter", CHAIN_FWD),
            Triple("iptables", "nat", CHAIN_FWD_DNS), Triple("ip6tables", "filter", CHAIN_V6_FWD),
            Triple("ip6tables", "mangle", CHAIN_V6_PRE),
        )) appendLine("if $cmd -t $table -S $chain >/dev/null 2>&1; then exit 1; fi")
        appendLine("[ \"\$CLEANUP_OK\" = 1 ] || exit 1")
        if (!byWatchdog) {
            appendLine("if [ -f '$dir/oomguard.pid' ] && [ -f '$dir/oomguard.start' ]; then PID=\$(cat '$dir/oomguard.pid'); if [ \"\$(cut -d' ' -f22 /proc/\$PID/stat 2>/dev/null)\" = \"\$(cat '$dir/oomguard.start')\" ]; then kill \$PID 2>/dev/null; fi; fi; rm -f '$dir/oomguard.pid' '$dir/oomguard.start'")
            appendLine("echo 0 > /proc/${Process.myPid()}/oom_score_adj 2>/dev/null")
        }
        appendLine("rm -f '$dir/owned'")
        if (byWatchdog) appendLine("rm -f '$dir/active'")
        append("true")
    }

    private fun runSu(script: String) {
        val file = File(runDir, "script.sh").apply { writeText(xtablesWait(script)) }
        val process = try {
            ProcessBuilder("su", "-c", "sh '${file.absolutePath}'").redirectErrorStream(true).start()
        } catch (e: IOException) {
            throw RootException(app.getString(R.string.transproxy_root_required))
        }
        var output = ""
        val reader = Thread {
            output = try {
                String(io.nekohasekai.sagernet.utils.BoundedInput.read(process.inputStream, 128 * 1024), Charsets.UTF_8)
            } catch (_: IOException) {
                ""
            }
        }
        reader.start()
        val deadline = android.os.SystemClock.elapsedRealtime() + SU_TIMEOUT_MS
        var exitCode: Int? = null
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            exitCode = try { process.exitValue() } catch (_: IllegalThreadStateException) { null }
            if (exitCode != null) break
            Thread.sleep(20)
        }
        if (exitCode == null) {
            process.destroy()
            process.inputStream.close()
            throw RootException("Root command timed out; cleanup will be retried")
        }
        reader.join(1000)
        if (exitCode != 0) {
            Logs.w("transproxy: su exited with $exitCode: $output")
            throw RootException(
                app.getString(R.string.transproxy_failed, output.trim().lines().lastOrNull() ?: "$exitCode")
            )
        }
    }
}
