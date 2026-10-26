package io.nekohasekai.sagernet.bg

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransproxyRulesTest {

    private val dnsRule = Regex("--dport 53 -j MARK")

    @Test
    fun proxyOnlyMarksOnlySelectedAppsDns() {
        val rules = Transproxy.markRules("iptables", listOf("10.0.0.0/8"), 10123, true, setOf(10200, 10300))
            .lines().filter { dnsRule.containsMatchIn(it) }
        // udp + tcp for each selected app, nothing for other apps
        assertEquals(4, rules.size)
        assertTrue(rules.all { it.contains("--uid-owner 10200") || it.contains("--uid-owner 10300") })
    }

    @Test
    fun allAppsModeMarksAllDns() {
        val rules = Transproxy.markRules("iptables", emptyList(), 10123, false, setOf(10200))
        val dns = rules.lines().filter { dnsRule.containsMatchIn(it) }
        assertEquals(2, dns.size)
        assertTrue(dns.none { it.contains("--uid-owner") })
        // bypassed app returns before the DNS rules
        val lines = rules.lines()
        assertTrue(lines.indexOfFirst { it.contains("--uid-owner 10200 -j RETURN") } < lines.indexOf(dns[0]))
    }

    @Test
    fun coreIsNeverMarked() {
        val rules = Transproxy.markRules("ip6tables", emptyList(), 10123, true, setOf(10200)).lines()
        assertTrue(rules[1].contains("--uid-owner 10123 -j RETURN"))
    }

    @Test
    fun xtablesWaitOnEveryCall() {
        val script = """
            iptables -t mangle -N NBZ_MARK
            while ip6tables -D OUTPUT -j NBZ6_REJECT 2>/dev/null; do :; done
            iptables -t nat -F NBZ_FWD_DNS 2>/dev/null; iptables -t nat -X NBZ_FWD_DNS
            ip rule add fwmark 0x2096 table 2096
        """.trimIndent()
        val out = Transproxy.xtablesWait(script)
        assertEquals(4, Regex("ip6?tables -w 5 ").findAll(out).count())
        assertFalse(out.contains("ip rule add fwmark 0x2096 table 2096 -w"))
        assertFalse(Regex("ip6?tables (?!-w 5)").containsMatchIn(out))
    }
}
