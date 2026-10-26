package io.nekohasekai.sagernet.utils

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.zip.DeflaterOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail
import org.junit.Test

class BoundedInputTest {
    private fun compressed(bytes: ByteArray) = ByteArrayOutputStream().also { out ->
        DeflaterOutputStream(out).use { it.write(bytes) }
    }.toByteArray()
    @Test fun acceptsCompleteStream() {
        val bytes = ByteArray(8192) { 42 }
        assertArrayEquals(bytes, BoundedInput.inflate(compressed(bytes), bytes.size))
    }
    @Test fun rejectsTruncationAndBomb() {
        val bytes = compressed(ByteArray(8192))
        for ((data, limit) in listOf(bytes.copyOf(bytes.size - 4) to 8192, bytes to 1024)) {
            try { BoundedInput.inflate(data, limit); fail("accepted invalid stream") } catch (_: IOException) {}
        }
    }
    @Test fun limitsBeforeParsingAndRejectsTraversal() {
        try { BoundedInput.read(ByteArrayInputStream(ByteArray(5)), 4); fail("accepted oversize") } catch (_: IOException) {}
        for (name in listOf("../database.db", "/database.db", "..\\database.db")) {
            try { BoundedInput.assetTarget(File("."), name); fail("accepted unsafe filename") } catch (_: IOException) {}
        }
    }
}
