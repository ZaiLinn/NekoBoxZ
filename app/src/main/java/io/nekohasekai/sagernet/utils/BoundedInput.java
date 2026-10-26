package io.nekohasekai.sagernet.utils;

import java.io.*;
import java.util.zip.*;

/** Limits apply before decoding or parsing untrusted content. */
public final class BoundedInput {
    public static final int MAX_TEXT = 32 * 1024 * 1024;
    public static final int MAX_ENTRIES = 10000;
    public static final int MAX_ASSET = 256 * 1024 * 1024;
    private BoundedInput() {}

    public static long copy(InputStream in, OutputStream out, long limit) throws IOException {
        if (limit < 0) throw new IOException("Invalid input size limit");
        byte[] buffer = new byte[8192];
        long total = 0;
        for (int n; (n = in.read(buffer, 0, (int)Math.min(buffer.length, limit - total + 1))) != -1;) {
            total += n;
            if (total > limit) throw new IOException("Input exceeds size limit");
            out.write(buffer, 0, n);
        }
        return total;
    }

    public static byte[] read(InputStream in, int limit) throws IOException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            copy(in, out, limit);
            return out.toByteArray();
        }
    }

    public static byte[] inflate(byte[] input, int limit) throws IOException, DataFormatException {
        Inflater inflater = new Inflater();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            inflater.setInput(input);
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n > limit - out.size()) throw new IOException("Decompressed input exceeds size limit");
                out.write(buffer, 0, n);
                if (n == 0 && !inflater.finished()) throw new IOException("Truncated or unsupported compressed input");
            }
            if (inflater.getRemaining() != 0) throw new IOException("Trailing compressed input");
            return out.toByteArray();
        } finally { inflater.end(); }
    }

    public static File assetTarget(File directory, String name) throws IOException {
        if (name.isEmpty() || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 ||
            name.indexOf('\0') >= 0 || !name.endsWith(".db")) throw new IOException("Invalid asset filename");
        File base = directory.getCanonicalFile();
        File result = new File(base, name).getCanonicalFile();
        if (!base.equals(result.getParentFile())) throw new IOException("Asset path escapes directory");
        return result;
    }
}
