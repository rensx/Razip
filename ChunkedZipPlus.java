import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;

import java.security.MessageDigest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class ChunkedZipPlus {

    public static final int DEFAULT_BLOCK_SIZE = 64 * 1024;
    public static final String ENV_BLOCK_SIZE = "CHUNKEDZIP_BLOCKSIZE";
    public static final String ENV_LEVEL = "CHUNKEDZIP_LEVEL";
    public static final int DEFAULT_COMPRESSION_LEVEL = Deflater.BEST_COMPRESSION; // 9
    public static final int INDEX_VERSION = 1;
    public static final int MAGIC = 0x7a696e64; // 'zind'

    public static void main(String[] args) {
        Options options = new Options();

        options.addOption("c", "compress", false, "Compress mode");
        options.addOption("d", "decompress", false, "Decompress mode");
        options.addOption("l", "list", false, "List chunks info");
        options.addOption("h", "help", false, "Show help");

        options.addOption(Option.builder()
                .argName("blocksize")
                .longOpt("blocksize")
                .hasArg()
                .desc("Block size to use (e.g. 64k, 128k, 65536)")
                .build());

        options.addOption(Option.builder()
                .argName("level")
                .longOpt("level")
                .hasArg()
                .desc("Compression level (0-9), 0=no compress, 9=max (default 9)")
                .build());

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);

            if (cmd.hasOption("h") || args.length == 0) {
                printHelp(options);
                return;
            }

            if (cmd.hasOption("c")) {
                String[] remaining = cmd.getArgs();
                if (remaining.length < 1 || remaining.length > 2) {
                    System.err.println("ERROR: For compression, specify input file and optional output file.");
                    printHelp(options);
                    return;
                }
                File input = new File(remaining[0]);
                if (!input.exists() || !input.isFile())
                    throw new IllegalArgumentException("Input file does not exist or is not a file: " + input);

                File output = (remaining.length > 1) ? new File(remaining[1])
                        : new File(getOutputFileName(input.getPath(), "compress"));

                int blockSize = getBlockSize(cmd);
                int compressionLevel = getCompressionLevel(cmd);

                compress(input, output, blockSize, compressionLevel);
                System.out.println("Compression done: " + output);
            } else if (cmd.hasOption("d")) {
                String[] remaining = cmd.getArgs();
                if (remaining.length != 1 && remaining.length != 2 && remaining.length !=4) {
                    System.err.println("ERROR: Decompress usage:");
                    System.err.println("  -d input");
                    System.err.println("  -d input output");
                    System.err.println("  -d input pos len output");
                    printHelp(options);
                    return;
                }

                File input = new File(remaining[0]);
                if (!input.exists() || !input.isFile())
                    throw new IllegalArgumentException("Input file does not exist or is not a file: " + input);

                long[] part = null;
                File output;

                if (remaining.length == 1) {
                    output = new File(getOutputFileName(input.getPath(), "decompress"));
                } else if (remaining.length == 2) {
                    output = new File(remaining[1]);
                } else {
                    // partial decompression
                    long pos = Long.parseLong(remaining[1]);
                    long len = Long.parseLong(remaining[2]);
                    if (pos < 0 || len <= 0)
                        throw new IllegalArgumentException("pos and len must be positive numbers.");
                    part = new long[]{pos, len};
                    output = new File(remaining[3]);
                }
                decompress(input, output, part);
                System.out.println("Decompression done: " + output);
            } else if (cmd.hasOption("l")) {
                String[] remaining = cmd.getArgs();
                if (remaining.length != 1) {
                    System.err.println("ERROR: List usage: -l input");
                    printHelp(options);
                    return;
                }
                File input = new File(remaining[0]);
                listInfo(input);
            } else {
                System.err.println("ERROR: No operation specified.");
                printHelp(options);
            }
        } catch (ParseException pe) {
            System.err.println("ERROR parsing command line: " + pe.getMessage());
            printHelp(options);
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private static int getBlockSize(CommandLine cmd) {
        int blockSize = DEFAULT_BLOCK_SIZE;

        if (cmd.hasOption("blocksize")) {
            String val = cmd.getOptionValue("blocksize").toLowerCase(Locale.ROOT).trim();
            try {
                if (val.endsWith("k")) {
                    blockSize = Integer.parseInt(val.substring(0, val.length() - 1)) * 1024;
                } else if (val.endsWith("m")) {
                    blockSize = Integer.parseInt(val.substring(0, val.length() - 1)) * 1024 * 1024;
                } else {
                    blockSize = Integer.parseInt(val);
                }
                if (blockSize <= 0) {
                    System.err.println("Blocksize must be a positive integer. Using default " + DEFAULT_BLOCK_SIZE);
                    blockSize = DEFAULT_BLOCK_SIZE;
                }
            } catch (NumberFormatException ex) {
                System.err.println("Invalid blocksize format. Using default " + DEFAULT_BLOCK_SIZE);
            }
        }

        String env = System.getenv(ENV_BLOCK_SIZE);
        if (env != null && !env.isEmpty()) {
            try {
                String envVal = env.toLowerCase(Locale.ROOT).trim();
                if (envVal.endsWith("k")) {
                    blockSize = Integer.parseInt(envVal.substring(0, envVal.length() - 1)) * 1024;
                } else if (envVal.endsWith("m")) {
                    blockSize = Integer.parseInt(envVal.substring(0, envVal.length() - 1)) * 1024 * 1024;
                } else {
                    blockSize = Integer.parseInt(envVal);
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return blockSize;
    }

    private static int getCompressionLevel(CommandLine cmd) {
        int level = DEFAULT_COMPRESSION_LEVEL;
        if (cmd.hasOption("level")) {
            String sval = cmd.getOptionValue("level").trim();
            try {
                level = Integer.parseInt(sval);
                if (level < Deflater.NO_COMPRESSION) level = Deflater.NO_COMPRESSION;
                if (level > Deflater.BEST_COMPRESSION) level = Deflater.BEST_COMPRESSION;
            } catch (NumberFormatException ex) {
                System.err.println("Invalid level, use 0-9. Defaulting to " + DEFAULT_COMPRESSION_LEVEL);
                level = DEFAULT_COMPRESSION_LEVEL;
            }
        } else {
            String env = System.getenv(ENV_LEVEL);
            if (env != null && !env.isEmpty()) {
                try {
                    int envLevel = Integer.parseInt(env.trim());
                    if (envLevel >= Deflater.NO_COMPRESSION && envLevel <= Deflater.BEST_COMPRESSION)
                        level = envLevel;
                } catch (NumberFormatException ignore) {}
            }
        }
        return level;
    }


    /**
     * 压缩文件成分块zip
     */
    public static void compress(File input, File output, int blockSize, int compressLevel) throws Exception {
        if (!input.exists() || !input.isFile())
            throw new IOException("Input file does not exist or is not a regular file: " + input.getPath());

        long fileSize = input.length();
        if (fileSize == 0) throw new IOException("Input file is empty.");

        int blockCount = (int) ((fileSize + blockSize - 1) / blockSize);

        System.out.printf("Compressing `%s` to `%s` (Block Size: %d, Blocks: %d, Level: %d)%n",
                input.getName(), output.getName(), blockSize, blockCount, compressLevel);

        byte[][] blocks = new byte[blockCount][];
        int[] blockActualSizes = new int[blockCount];

        try (InputStream in = new BufferedInputStream(new FileInputStream(input))) {
            for (int i = 0; i < blockCount; i++) {
                int toRead = (int) Math.min(blockSize, fileSize - (long) i * blockSize);
                byte[] buf = new byte[toRead];
                int offset = 0;
                while (offset < toRead) {
                    int n = in.read(buf, offset, toRead - offset);
                    if (n < 0) throw new IOException("Unexpected EOF when reading file");
                    offset += n;
                }
                blocks[i] = buf;
                blockActualSizes[i] = toRead;

                printProgress(i + 1, blockCount, "Reading blocks");
            }
        }

        // 多线程压缩
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(blockCount, Runtime.getRuntime().availableProcessors()));
        List<Future<byte[]>> compressedFutures = new ArrayList<>(blockCount);

        for (int i = 0; i < blockCount; i++) {
            final int idx = i;
            compressedFutures.add(pool.submit(() -> compressBlock(blocks[idx], compressLevel)));
        }
        pool.shutdown();

        if (!pool.awaitTermination(1, TimeUnit.HOURS)) {
            throw new IOException("Compression tasks timed out.");
        }

        // 计算CRC和SHA256
        CRC32 crc32 = new CRC32();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (byte[] block : blocks) {
            crc32.update(block);
            sha256.update(block);
        }
        long crcValue = crc32.getValue();
        byte[] sha256Sum = sha256.digest();

        try (ZipOutputStream zout = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)))) {
            zout.setLevel(compressLevel);

            for (int i = 0; i < blockCount; i++) {
                byte[] compressedBlock = compressedFutures.get(i).get();
                ZipEntry entry = new ZipEntry(String.format("block_%05d", i + 1));
                zout.putNextEntry(entry);
                zout.write(compressedBlock);
                zout.closeEntry();

                printProgress(i + 1, blockCount, "Writing compressed blocks");
            }

            byte[] indexData = buildIndex(INDEX_VERSION, fileSize, blockCount, blockSize, blockActualSizes, crcValue, sha256Sum);
            ZipEntry indexEntry = new ZipEntry("index");
            zout.putNextEntry(indexEntry);
            zout.write(indexData);
            zout.closeEntry();
        }

        System.out.printf("Compression completed.\nCRC32: %08x\nSHA-256: %s%n", crcValue, bytesToHex(sha256Sum));
    }

    private static void printProgress(int done, int total, String message) {
        int percent = (int) ((done * 100L) / total);
        System.out.printf("\r%s: %3d%% (%d/%d)", message, percent, done, total);
        if (done == total)
            System.out.println();
    }

    private static byte[] compressBlock(byte[] data, int compressLevel) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(compressLevel);
        try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
            dos.write(data);
        } finally {
            deflater.end();
        }
        return baos.toByteArray();
    }

    /**
     * 解压文件或文件部分
     */
    public static void decompress(File input, File output, long[] part) throws Exception {
        if (!input.exists() || !input.isFile())
            throw new IOException("Input file does not exist or is not a regular file: " + input.getPath());

        ChunkedIndex index = readIndex(input);

        // 检查输出路径，防止目录遍历攻击（Zip Slip） - 由于只写入单一输出文件，检查输出文件不在压缩包中即可
        if (output.exists()) {
            if (output.isDirectory()) {
                throw new IOException("Output must be a file, not a directory.");
            }
            if (!output.canWrite()) {
                throw new IOException("Output file is not writable.");
            }
        } else {
            File parent = output.getCanonicalFile().getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IOException("Cannot create output directory: " + parent);
            }
        }

        try (ZipFile zipFile = new ZipFile(input);
             RandomAccessFile raf = new RandomAccessFile(output, "rw")) {

            raf.setLength(0); // 清空文件

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            CRC32 verifyCrc = new CRC32();

            if (part == null) {
                int totalBlocks = index.blockCount;
                for (int i = 0; i < totalBlocks; i++) {
                    String blockName = String.format("block_%05d", i + 1);
                    ZipEntry entry = zipFile.getEntry(blockName);
                    if (entry == null)
                        throw new IOException("Missing compressed block: " + blockName);

                    byte[] decompressed = decompressBlock(zipFile.getInputStream(entry), index.chunkSizes[i]);

                    verifyCrc.update(decompressed);
                    sha256.update(decompressed);

                    raf.write(decompressed);
                    printProgress(i + 1, totalBlocks, "Decompressing blocks");
                }
            } else {
                long pos = part[0];
                long len = part[1];

                if (pos < 0 || len <= 0 || pos + len > index.originalSize) {
                    throw new IllegalArgumentException("Invalid decompression range specified.");
                }

                int startBlock = (int) (pos / index.blockSize);
                int endBlock = (int) ((pos + len - 1) / index.blockSize);
                long currentOffset = (long) startBlock * index.blockSize;

                long bytesRemaining = len;

                for (int blockIdx = startBlock; blockIdx <= endBlock; blockIdx++) {
                    String blockName = String.format("block_%05d", blockIdx + 1);
                    ZipEntry entry = zipFile.getEntry(blockName);
                    if (entry == null)
                        throw new IOException("Missing compressed block: " + blockName);

                    byte[] decompressed = decompressBlock(zipFile.getInputStream(entry), index.chunkSizes[blockIdx]);

                    verifyCrc.update(decompressed);
                    sha256.update(decompressed);

                    int blockStart = 0;
                    int blockEnd = decompressed.length;

                    if (currentOffset < pos) {
                        blockStart = (int) (pos - currentOffset);
                    }
                    if (currentOffset + decompressed.length > pos + len) {
                        blockEnd = (int) (pos + len - currentOffset);
                    }

                    int writeLen = blockEnd - blockStart;
                    if (writeLen > 0) {
                        raf.write(decompressed, blockStart, writeLen);
                        bytesRemaining -= writeLen;
                    }

                    currentOffset += decompressed.length;
                    printProgress(blockIdx - startBlock + 1, endBlock - startBlock + 1, "Decompressing partial blocks");
                }

                if (bytesRemaining != 0)
                    throw new IOException("Unable to decompress full requested range.");
            }

            if (verifyCrc.getValue() != index.crc || !Arrays.equals(sha256.digest(), index.sha256)) {
                throw new IOException("Data integrity verification failed (CRC32 or SHA256 mismatch).");
            }

            System.out.println("Decompression successful and verified.");
        }
    }

    private static byte[] decompressBlock(InputStream compressedStream, int expectedSize) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(expectedSize);
        try (InflaterInputStream inflaterIn = new InflaterInputStream(compressedStream)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inflaterIn.read(buffer)) != -1) {
                baos.write(buffer, 0, read);
            }
        }
        byte[] decompressed = baos.toByteArray();
        if (decompressed.length != expectedSize) {
            throw new IOException("Decompressed block size mismatch. Expected "
                    + expectedSize + " bytes, got " + decompressed.length);
        }

        return decompressed;
    }

    /**
     * 读取索引数据，并支持版本控制
     */
    public static ChunkedIndex readIndex(File zipFile) throws IOException {
        try (ZipFile zf = new ZipFile(zipFile)) {
            ZipEntry indexEntry = zf.getEntry("index");
            if (indexEntry == null) {
                throw new IOException("Missing index entry in zip file.");
            }

            try (InputStream in = zf.getInputStream(indexEntry)) {
                DataInputStream dataIn = new DataInputStream(in);

                int magic = dataIn.readInt();
                if (magic != MAGIC) {
                    throw new IOException("Invalid index magic number.");
                }

                int version = dataIn.readInt();
                if (version != INDEX_VERSION) {
                    throw new IOException("Unsupported index version: " + version);
                }

                long originalSize = dataIn.readLong();
                int blockCount = dataIn.readInt();
                int blockSize = dataIn.readInt();
                long crc = dataIn.readLong();

                int shaLen = dataIn.readInt();
                if (shaLen <=0 || shaLen > 64){
                    throw new IOException("Invalid SHA256 length in index.");
                }

                byte[] sha256 = new byte[shaLen];
                dataIn.readFully(sha256);

                int[] chunkSizes = new int[blockCount];
                for (int i = 0; i < blockCount; i++) {
                    chunkSizes[i] = dataIn.readInt();
                    if (chunkSizes[i] <= 0 || chunkSizes[i] > blockSize) {
                        throw new IOException("Invalid chunk size in index at block " + i + ": " + chunkSizes[i]);
                    }
                }
                return new ChunkedIndex(originalSize, blockCount, blockSize, chunkSizes, crc, sha256);
            }
        }
    }

    private static byte[] buildIndex(int version, long totalSize, int blockCount, int blockSize, int[] chunkSizes, long crc, byte[] sha256) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dataOut = new DataOutputStream(baos)) {

            dataOut.writeInt(MAGIC);
            dataOut.writeInt(version);
            dataOut.writeLong(totalSize);
            dataOut.writeInt(blockCount);
            dataOut.writeInt(blockSize);
            dataOut.writeLong(crc);

            dataOut.writeInt(sha256.length);
            dataOut.write(sha256);

            for (int size : chunkSizes) {
                dataOut.writeInt(size);
            }
            return baos.toByteArray();
        }
    }

    public static class ChunkedIndex {
        public final long originalSize;
        public final int blockCount;
        public final int blockSize;
        public final int[] chunkSizes;
        public final long crc;
        public final byte[] sha256;

        public ChunkedIndex(long originalSize, int blockCount, int blockSize, int[] chunkSizes, long crc, byte[] sha256) {
            this.originalSize = originalSize;
            this.blockCount = blockCount;
            this.blockSize = blockSize;
            this.chunkSizes = chunkSizes;
            this.crc = crc;
            this.sha256 = sha256;
        }
    }

    /**
     * 防止 Zip Slip 漏洞的安全检查，判断 entryName 是否安全
     */
    private static void preventZipSlip(String entryName) throws IOException {
        File f = new File(entryName);
        String canonical = f.getCanonicalPath();
        if (canonical.contains("..") || canonical.contains(":") || canonical.startsWith(File.separator)) {
            throw new IOException("Unsafe entry name detected (possible Zip Slip attack): " + entryName);
        }
    }

    /**
     * 列出压缩包索引信息和内容
     */
    public static void listInfo(File zipFile) throws IOException {
        if (!zipFile.exists() || !zipFile.isFile()) {
            throw new IOException("File does not exist or is not a regular file: " + zipFile.getPath());
        }
        System.out.printf("File: %s (%d bytes)%n", zipFile.getName(), zipFile.length());

        try {
            ChunkedIndex index = readIndex(zipFile);
            System.out.printf("Index Version: %d%n", INDEX_VERSION);
            System.out.printf("Original Size: %d bytes%n", index.originalSize);
            System.out.printf("Block Count: %d%n", index.blockCount);
            System.out.printf("Block Size: %d bytes%n", index.blockSize);
            System.out.printf("CRC32: %08x%n", index.crc);
            System.out.printf("SHA-256: %s%n", bytesToHex(index.sha256));

            System.out.println("Chunk Sizes:");
            for (int i = 0; i < index.blockCount; i++) {
                System.out.printf("  Block %d: %d bytes%n", (i + 1), index.chunkSizes[i]);
            }
        } catch (IOException e) {
            System.err.println("Failed to read index: " + e.getMessage());
        }

        System.out.println("Entries:");
        try (ZipFile zf = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                System.out.printf("  %s (%d bytes)%n", entry.getName(), entry.getSize());
            }
        }
    }

    /**
     * 按照操作默认生成输出文件名
     */
    public static String getOutputFileName(String inputFileName, String operation) {
        File inputFile = new File(inputFileName);
        String parent = inputFile.getParent();
        String name = inputFile.getName();
        String out;

        if ("compress".equalsIgnoreCase(operation)) {
            if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                out = name;
            } else {
                out = name + ".zip";
            }
        } else if ("decompress".equalsIgnoreCase(operation)) {
            if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
                out = name.substring(0, name.length() - 4);
                if (out.isEmpty()) {
                    out = "output";
                }
            } else {
                out = name + ".decompressed";
            }
        } else {
            throw new IllegalArgumentException("Unknown operation: " + operation);
        }

        return (parent != null) ? new File(parent, out).getPath() : out;
    }

    /**
     * 辅助字节数组转十六进制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        String header = "\nExamples:\n" +
                "  java ChunkedZip -c input.txt --blocksize 64k --level 6\n" +
                "  java ChunkedZip -d archive.zip output.txt\n" +
                "  java ChunkedZip -d archive.zip 0 1024 part1.dat\n" +
                "  java ChunkedZip -l archive.zip\n";
        formatter.printHelp("java ChunkedZip [options] [arguments]", header, options, null);
    }
}