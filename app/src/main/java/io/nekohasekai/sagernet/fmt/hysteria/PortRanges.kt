package io.nekohasekai.sagernet.fmt.hysteria

/** sing-box represents an individual hopping port as a one-element range. */
fun hopPortsToSingboxList(s: String): List<String> = s.split(',').map { item ->
    val bounds = item.trim().replace('-', ':').split(':')
    require(bounds.size in 1..2) { "Invalid port range" }
    val first = bounds[0].toIntOrNull() ?: error("Invalid port")
    val last = if (bounds.size == 1) first else bounds[1].toIntOrNull() ?: error("Invalid port")
    require(first in 1..65535 && last in first..65535) { "Port out of range" }
    "$first:$last"
}
