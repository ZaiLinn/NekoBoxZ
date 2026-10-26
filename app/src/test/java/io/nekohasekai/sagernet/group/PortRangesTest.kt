package io.nekohasekai.sagernet.group

import io.nekohasekai.sagernet.fmt.hysteria.hopPortsToSingboxList
import org.junit.Assert.assertEquals
import org.junit.Test

class PortRangesTest {
    @Test fun keepsSinglesAlongsideRanges() {
        assertEquals(listOf("443:443", "8443:8443"), hopPortsToSingboxList("443,8443"))
        assertEquals(listOf("443:443", "10000:20000"), hopPortsToSingboxList("443,10000-20000"))
    }
    @Test(expected = IllegalArgumentException::class)
    fun rejectsInvalidRange() { hopPortsToSingboxList("20000-10000") }
}
