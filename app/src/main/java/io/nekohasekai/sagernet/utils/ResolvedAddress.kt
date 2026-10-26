package io.nekohasekai.sagernet.utils

import io.nekohasekai.sagernet.IPv6Mode
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

fun selectResolvedAddress(addresses: List<InetAddress>, mode: Int): InetAddress {
    val allowed = addresses.filter {
        when (mode) {
            IPv6Mode.DISABLE -> it is Inet4Address
            IPv6Mode.ONLY -> it is Inet6Address
            else -> true
        }
    }
    val preferV6 = mode >= IPv6Mode.PREFER
    return allowed.firstOrNull { (it is Inet6Address) == preferV6 }
        ?: allowed.firstOrNull() ?: throw UnknownHostException("No address in the enabled IP family")
}
