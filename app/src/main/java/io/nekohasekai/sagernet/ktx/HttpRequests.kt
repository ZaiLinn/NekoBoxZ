package io.nekohasekai.sagernet.ktx

import kotlinx.coroutines.suspendCancellableCoroutine
import libcore.HTTPRequest
import libcore.HTTPResponse

/** Keep JNI cancellation connected through the entire response read, not just its headers. */
suspend fun <T> HTTPRequest.useResponse(read: (HTTPResponse) -> T): T = suspendCancellableCoroutine { c ->
    c.invokeOnCancellation { cancel() }
    runOnIoDispatcher {
        val result = runCatching {
            val response = execute()
            try { read(response) } finally { response.close() }
        }
        c.resumeWith(result)
    }
}

suspend fun <T> okhttp3.Call.useResponse(read: (okhttp3.Response) -> T): T = suspendCancellableCoroutine { c ->
    c.invokeOnCancellation { cancel() }
    runOnIoDispatcher {
        c.resumeWith(runCatching { execute().use(read) })
    }
}
