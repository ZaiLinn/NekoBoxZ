package io.nekohasekai.sagernet.utils

import io.nekohasekai.sagernet.IPv6Mode
import java.net.InetAddress
import java.net.UnknownHostException
import org.junit.Assert.assertEquals
import org.junit.Test

class ResolvedAddressTest {
    private val v4 = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1))
    private val v6 = InetAddress.getByAddress(ByteArray(16).apply { this[15] = 1 })
    @Test fun honorsFamiliesAndPreference() {
        val both = listOf(v6, v4)
        assertEquals(v4, selectResolvedAddress(both, IPv6Mode.DISABLE))
        assertEquals(v4, selectResolvedAddress(both, IPv6Mode.ENABLE))
        assertEquals(v6, selectResolvedAddress(both, IPv6Mode.PREFER))
        assertEquals(v6, selectResolvedAddress(both, IPv6Mode.ONLY))
    }
    @Test(expected = UnknownHostException::class)
    fun disabledIpv6NeverBecomesNodeAddress() { selectResolvedAddress(listOf(v6), IPv6Mode.DISABLE) }
}
