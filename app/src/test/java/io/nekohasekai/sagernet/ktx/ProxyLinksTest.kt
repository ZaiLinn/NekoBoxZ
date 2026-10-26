package io.nekohasekai.sagernet.ktx

import io.nekohasekai.sagernet.fmt.http.parseHttp
import io.nekohasekai.sagernet.ktx.ImportSkipReason.INVALID_PROXY_LINK
import io.nekohasekai.sagernet.ktx.ImportSkipReason.SUBSCRIPTION_LINK
import io.nekohasekai.sagernet.ktx.ImportSkipReason.UNSUPPORTED
import io.nekohasekai.sagernet.ktx.ImportSkipReason.WEB_LINK
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests the line handling of the proxy link import. The real per-scheme parsers log through the
 * native core, so a stand-in with the same classification is used here: a link of a proxy
 * scheme parses unless it contains "broken", an http(s) link is a proxy only when its path is
 * "/", which is what [parseHttp] checks.
 */
class ProxyLinksTest {

    private val proxySchemes = listOf("vmess://", "vless://", "trojan://", "ss://", "hy2://", "tuic://")

    private fun fakeParse(link: String): LinkParseResult<String> = when {
        link.startsWith("clash://install-config?") || link.startsWith("sn://subscription?") ->
            LinkParseResult.Skipped(SUBSCRIPTION_LINK)

        link.startsWith("http://") || link.startsWith("https://") ->
            if (runCatching { parseHttp(link) }.isSuccess) LinkParseResult.Proxy(link)
            else LinkParseResult.Skipped(WEB_LINK)

        proxySchemes.any { link.startsWith(it) } ->
            if ("broken" in link) LinkParseResult.Skipped(INVALID_PROXY_LINK)
            else LinkParseResult.Proxy(link)

        else -> LinkParseResult.Skipped(UNSUPPORTED)
    }

    private fun collect(text: String) = collectProxyLinks(text, ::fakeParse)

    @Test
    fun singleProxy() {
        val links = collect("vmess://abc")
        assertEquals(listOf("vmess://abc"), links.result.proxies)
        assertEquals(0, links.result.skippedCount)
        assertNull(links.subscriptionLink)
    }

    @Test
    fun severalProtocols() {
        val links = collect("vmess://a\nvless://b\r\ntrojan://c\nss://d\nhy2://e\ntuic://f\nhttp://user:pass@1.2.3.4:8080")
        assertEquals(
            listOf("vmess://a", "vless://b", "trojan://c", "ss://d", "hy2://e", "tuic://f", "http://user:pass@1.2.3.4:8080"),
            links.result.proxies
        )
        assertEquals(0, links.result.skippedCount)
    }

    @Test
    fun subscriptionUrlAlone() {
        val url = "https://sub.example.com/api/v1/client/subscribe?token=abc"
        val links = collect("  $url \n")
        assertTrue(links.result.proxies.isEmpty())
        assertEquals(url, links.subscriptionLink)
    }

    @Test
    fun explicitSubscriptionLinkAlone() {
        val links = collect("clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub")
        assertEquals("clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub", links.subscriptionLink)
    }

    @Test
    fun webLinkDoesNotDropProxies() {
        // before the fix, the web link threw SubscriptionFoundException and dropped vmess://a
        val links = collect("vmess://a\nhttps://t.me/some_channel\ntrojan://b")
        assertEquals(listOf("vmess://a", "trojan://b"), links.result.proxies)
        assertEquals(mapOf(WEB_LINK to 1), links.result.skipped)
        assertNull(links.subscriptionLink)
    }

    @Test
    fun webLinkBeforeProxies() {
        val links = collect("https://github.com/some/repo\nvmess://a")
        assertEquals(listOf("vmess://a"), links.result.proxies)
        assertNull(links.subscriptionLink)
    }

    @Test
    fun subscriptionLinkNextToProxiesIsSkipped() {
        val links = collect("vmess://a\nclash://install-config?url=x")
        assertEquals(listOf("vmess://a"), links.result.proxies)
        assertEquals(mapOf(SUBSCRIPTION_LINK to 1), links.result.skipped)
        assertNull(links.subscriptionLink)
    }

    @Test
    fun fileWithInvalidLines() {
        val text = """
            # my nodes
            vmess://a
            vmess://broken
            just some text

            ss://b
        """.trimIndent()
        val links = collect(text)
        assertEquals(listOf("vmess://a", "ss://b"), links.result.proxies)
        assertEquals(mapOf(UNSUPPORTED to 2, INVALID_PROXY_LINK to 1), links.result.skipped)
        assertEquals(3, links.result.skippedCount)
    }

    @Test
    fun lineWithLabelAndLink() {
        // split by spaces finds the link, the label on the same line is not counted as skipped
        val links = collect("Node 1: vmess://a\nNode 2: trojan://b")
        assertEquals(listOf("vmess://a", "trojan://b"), links.result.proxies)
        assertEquals(0, links.result.skippedCount)
    }

    @Test
    fun severalWebLinksAreNotASubscription() {
        val links = collect("https://example.com/a\nhttps://example.com/b")
        assertTrue(links.result.proxies.isEmpty())
        assertEquals(mapOf(WEB_LINK to 2), links.result.skipped)
        assertNull(links.subscriptionLink)
    }

    @Test
    fun textWithOneWebLinkIsNotASubscription() {
        val links = collect("see https://example.com/page for details")
        assertTrue(links.result.proxies.isEmpty())
        assertNull(links.subscriptionLink)
    }

    @Test
    fun emptyText() {
        for (text in listOf("", "\n\n", "   \n \t ")) {
            val links = collect(text)
            assertTrue(links.result.proxies.isEmpty())
            assertEquals(0, links.result.skippedCount)
            assertNull(links.subscriptionLink)
        }
    }

    @Test
    fun httpProxyAndWebPage() {
        // the rule the http(s) classification depends on
        assertEquals(8080, parseHttp("http://user:pass@1.2.3.4:8080").serverPort)
        assertTrue(runCatching { parseHttp("https://t.me/some_channel") }.isFailure)
    }

    @Test
    fun clashSubscriptionLink() {
        assertEquals(
            "clash://install-config/?url=https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Da",
            toClashSubscriptionLink("https://example.com/sub?token=a")
        )
    }
    @Test
    fun largeSubscriptionSurvivesOneInvalidLink() {
        // Upstream #1130: one bad entry must not reject a 650-node subscription.
        val valid = (1..650).map { "vless://node-$it" }
        val result = collect((valid + "vless://broken").joinToString("\n"))
        assertEquals(valid, result.result.proxies)
        assertEquals(1, result.result.skipped[INVALID_PROXY_LINK])
    }

}
