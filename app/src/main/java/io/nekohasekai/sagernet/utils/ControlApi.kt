package io.nekohasekai.sagernet.utils

import android.net.Uri
import io.nekohasekai.sagernet.ktx.app
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom

object ControlApi {
    @Synchronized
    fun secret(): String {
        val file = File(app.noBackupFilesDir, "clash-api-secret")
        return RandomAccessFile(file, "rw").use { output ->
            output.channel.lock().use {
                val current = if (output.length() == 64L) ByteArray(64).also { output.readFully(it) }.toString(Charsets.US_ASCII) else ""
                if (current.matches(Regex("[0-9a-f]{64}"))) current else {
                    val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
                    val value = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
                    output.setLength(0)
                    output.seek(0)
                    output.write(value.toByteArray(Charsets.US_ASCII))
                    output.fd.sync()
                    value
                }
            }
        }
    }

    fun panelUrl(url: String): String {
        val uri = Uri.parse(url)
        // Never disclose the local control credential to a user-specified remote page.
        if (uri.scheme != "http" || uri.host !in setOf("127.0.0.1", "localhost") || uri.port != 9090) return url
        return uri.buildUpon().clearQuery().apply {
            uri.queryParameterNames.filter { it != "secret" }.forEach { key ->
                uri.getQueryParameters(key).forEach { appendQueryParameter(key, it) }
            }
            appendQueryParameter("secret", secret())
        }.build().toString()
    }
}
