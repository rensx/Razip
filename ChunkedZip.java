import java.io.*;
import java.util.*;
import java.util.zip.*;

/**
 * ChunkedZip - 支持块压缩索引、部分解压的.zip文件格式
 * 每个块对应一个 zip entry(block_00001等)，index为索引entry，支持快速随机部分读取
 */
public class ChunkedZip {
    public static final int DEFAULT_BLOCK_SIZE = 16 * 1024; // 64KB
    public static final int BUFFER_SIZE = 64 * 1024;

    /**
     * 主入口.
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            printHelp();
            return;
        }
        String op = args[0].toLowerCase();
        try {
            switch (op) {
                case "-c":
                    if (args.length < 2 || args.length > 3) {
                        System.err.println("Usage: java ChunkedZip -c input [output]");
                        printHelp();
                        return;
                    }
                    String cinput = args[1];
                    String coutput = (args.length == 3) ? args[2] : getOutputFileName(cinput, "compress");
                    compress(new File(cinput), new File(coutput));
                    System.out.println("Compression done: " + coutput);
                    break;
                case "-d":
                    if (args.length == 2 || args.length == 3) {
                        String dinput = args[1];
                        String doutput = (args.length == 3) ? args[2] : getOutputFileName(dinput, "decompress");
                        decompress(new File(dinput), new File(doutput));
                        System.out.println("Decompression done: " + doutput);
                    } else if (args.length == 4 || args.length == 5) {
                        String dinput = args[1];
                        long pos = Long.parseLong(args[2]);
                        int len = Integer.parseInt(args[3]);
                        String doutput = (args.length == 5) ? args[4] : getOutputFileName(dinput, "decompress");
                        decompress(new File(dinput), new File(doutput), pos, len);
                        System.out.println("Partial decompression done: " + doutput);
                    } else {
                        System.err.println("Usage: java ChunkedZip -d input [pos len] [output]");
                        printHelp();
                    }
                    break;
                case "-l":
                    if (args.length != 2) {
                        System.err.println("Usage: java ChunkedZip -l input");
                        printHelp();
                        return;
                    }
                    listInfo(new File(args[1]));
                    break;
                case "-h":
                case "--help":
                    printHelp();
                    break;
                default:
                    System.err.println("Unknown option: " + op);
                    printHelp();
                    break;
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 压缩(块分割，zip多entry)
     */
    public static void compress(File input, File output) throws IOException {
        List<Long> chunkOffsets = new ArrayList<>();
        List<Integer> chunkSizes = new ArrayList<>();
        long totalSize = 0;
        int blockSize = DEFAULT_BLOCK_SIZE;

        try (InputStream in = new BufferedInputStream(new FileInputStream(input));
             ZipOutputStream zout = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(output)))
        ) {
            // Store block size, total size, entry counts in 'index' entry
            // Chunk data: blocks named block_00001等

            int blockId = 0;
            byte[] buf = new byte[blockSize];
            int len;
            CRC32 crc = new CRC32();
            while ((len = in.read(buf)) > 0) {
                blockId++;
                totalSize += len;
                crc.update(buf, 0, len);

                String entryName = String.format("block_%05d", blockId);
                ZipEntry entry = new ZipEntry(entryName);
                entry.setMethod(ZipEntry.DEFLATED);
                zout.putNextEntry(entry);
                zout.write(buf, 0, len);
                zout.closeEntry();

                chunkSizes.add(len);
            }
            // 写入索引entry
            ZipEntry indexEntry = new ZipEntry("index");
            indexEntry.setMethod(ZipEntry.STORED);
            byte[] indexData = buildIndex(totalSize, blockId, blockSize, chunkSizes, crc.getValue());
            indexEntry.setSize(indexData.length);
            indexEntry.setCompressedSize(indexData.length);
            indexEntry.setCrc(calcCRC(indexData));
            zout.putNextEntry(indexEntry);
            zout.write(indexData);
            zout.closeEntry();
        }
    }

    // 构造索引数据
    private static byte[] buildIndex(long totalSize, int blockCount, int blockSize, List<Integer> chunkSizes, long crcVal) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dout = new DataOutputStream(baos);
        dout.writeInt(0x7a696e64); // magic "zind"
        dout.writeLong(totalSize);
        dout.writeInt(blockCount);
        dout.writeInt(blockSize);
        dout.writeLong(crcVal); // for integrity
        for (int s : chunkSizes) dout.writeInt(s);
        dout.close();
        return baos.toByteArray();
    }

    private static long calcCRC(byte[] b) {
        CRC32 c = new CRC32();
        c.update(b);
        return c.getValue();
    }

    // 全文件解压
    public static void decompress(File input, File output) throws IOException {
        ChunkedIndex idx = readIndex(input);
        int blocks = idx.blockCount;
        int blockSize = idx.blockSize;
        try (ZipFile zf = new ZipFile(input);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
            for (int i = 1; i <= blocks; i++) {
                String entryName = String.format("block_%05d", i);
                ZipEntry ze = zf.getEntry(entryName);
                if (ze == null) throw new IOException("Missing data block: " + entryName);
                try (InputStream in = zf.getInputStream(ze)) {
                    copy(in, out);
                }
            }
        }
    }

    // 部分内容解压
    public static void decompress(File input, File output, long start, int length) throws IOException {
        ChunkedIndex idx = readIndex(input);
        int blockSize = idx.blockSize;
        int blockStart = (int) (start / blockSize) + 1;
        int blockEnd = (int) ((start + length - 1) / blockSize) + 1;
        int blocks = idx.blockCount;

        try (ZipFile zf = new ZipFile(input);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
            long remain = length;
            long writeStart = start;
            for (int i = blockStart; i <= blockEnd && remain > 0 && i <= blocks; i++) {
                String entryName = String.format("block_%05d", i);
                ZipEntry ze = zf.getEntry(entryName);
                if (ze == null) throw new IOException("Missing data block: " + entryName);
                try (InputStream in = zf.getInputStream(ze)) {
                    byte[] buf = new byte[blockSize];
                    int blen = in.read(buf);
                    if (blen < 0) blen = 0;
                    long blockDataStart = (long) (i - 1) * blockSize;
                    long blockDataEnd = blockDataStart + blen;
                    long readStart = Math.max(blockDataStart, writeStart);
                    long readEnd = Math.min(blockDataEnd, start + length);

                    if (readEnd > readStart) {
                        int off = (int) (readStart - blockDataStart);
                        int toWrite = (int) (readEnd - readStart);
                        out.write(buf, off, toWrite);
                        remain -= toWrite;
                        writeStart += toWrite;
                    }
                }
            }
        }
    }

    // 读��索引(从index entry)
    public static ChunkedIndex readIndex(File zf) throws IOException {
        try (ZipFile z = new ZipFile(zf)) {
            ZipEntry e = z.getEntry("index");
            if (e == null) throw new IOException("Index entry not found");
            try (InputStream in = z.getInputStream(e)) {
                DataInputStream din = new DataInputStream(in);
                int magic = din.readInt();
                if (magic != 0x7a696e64) throw new IOException("Not valid chunked zip index");
                long origSize = din.readLong();
                int count = din.readInt();
                int bsize = din.readInt();
                long crc = din.readLong();
                int[] chunkSizes = new int[count];
                for (int i = 0; i < count; i++) chunkSizes[i] = din.readInt();
                return new ChunkedIndex(origSize, count, bsize, chunkSizes, crc);
            }
        }
    }

    public static class ChunkedIndex {
        public final long originalSize;
        public final int blockCount;
        public final int blockSize;
        public final int[] chunkSizes;
        public final long crc;

        public ChunkedIndex(long s, int c, int bs, int[] sz, long crc) {
            this.originalSize = s;
            this.blockCount = c;
            this.blockSize = bs;
            this.chunkSizes = sz;
            this.crc = crc;
        }
    }

    public static void printHelp() {
        System.out.println(
            "Usage: java ChunkedZip [options] [file] ...\n\n"
            + "Options:\n"
            + "  -c input [output]            compress input file\n"
            + "  -d input [output]            decompress ENTIRE input file\n"
            + "  -d input pos len [output]    decompress input file from pos for len bytes\n"
            + "  -l input                     list info of input file\n"
            + "  -h                           show this help\n"
        );
    }

    public static void listInfo(File inputFile) throws IOException {
        try (ZipFile zf = new ZipFile(inputFile)) {
            int dblocks = 0, blockSize = -1;
            long orig = -1;
            long size = inputFile.length();
            long crc = -1;
            try {
                ChunkedIndex idx = readIndex(inputFile);
                dblocks = idx.blockCount; blockSize = idx.blockSize; orig = idx.originalSize; crc = idx.crc;
                System.out.println("ChunkedZip File:");
                System.out.println("  Block Size: " + blockSize);
                System.out.println("  Original File Size: " + orig + " bytes");
                System.out.println("  Compressed Size: " + size + " bytes");
                System.out.println("  Block Count: " + dblocks);
                System.out.println("  CRC32: " + String.format("%08x", crc));
            } catch (Exception ex) {
                System.out.println("  (Failed to reconstruct index: " + ex + ")");
            }

            // list entries
            System.out.println("  Data Blocks:");
            Enumeration<? extends ZipEntry> ens = zf.entries();
            while (ens.hasMoreElements()) {
                ZipEntry ent = ens.nextElement();
                System.out.printf("    %s (%d bytes)\n", ent.getName(), ent.getSize());
            }
        }
    }

    // 生成输出文件名
    public static String getOutputFileName(String inputFileName, String op) {
        File inputFile = new File(inputFileName);
        String parent = inputFile.getParent();
        String name = inputFile.getName();
        String outputName;
        if ("compress".equalsIgnoreCase(op)) {
            if (name.toLowerCase().endsWith(".zip"))
                outputName = name;
            else
                outputName = name + ".zip";
        } else if ("decompress".equalsIgnoreCase(op)) {
            if (name.toLowerCase().endsWith(".zip")) {
                outputName = name.substring(0, name.length() - 4);
                if (outputName.isEmpty()) outputName = "output";
            } else {
                outputName = name + ".decompressed";
            }
        } else {
            return null;
        }
        return parent != null ? new File(parent, outputName).getPath() : outputName;
    }

    /* bytes copy */
    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[BUFFER_SIZE];
        int r;
        while ((r = in.read(buf)) > 0) out.write(buf, 0, r);
    }
}