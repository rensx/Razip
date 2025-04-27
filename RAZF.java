import java.io.*;
import java.util.*;
import java.util.zip.*;

/**
 * RAZF - 一种支持块压缩的文件格式，具有索引信息，支持快速部分解压
 * Reference:https://github.com/lh3/samtools
 */
public class RAZF {
    // 默认块大小，用户可配置
    public static final int DEFAULT_BLOCK_SIZE = 64 * 1024; // 64 KB
    public static final int BUFFER_SIZE = 65536; // 64 KB缓冲区
    public static final byte[] MAGIC = { 'R', 'A', 'Z', 'F' }; // 文件标志 Header
    public static final int GZIP_HEADER_SIZE = 10; // GZIP头长度
    public static final byte GZIP_ID1 = 0x1f;
    public static final byte GZIP_ID2 = (byte) 0x8b;
    public static final byte GZIP_CM = 8; // 压缩方法：Deflate
    public static final byte GZIP_FLG = 4; // 说明含有FEXTRA字段
    public static final byte GZIP_OS = 3;  // 操作系统类型（Unix）

    // 索引部分MAGIC
    public static final byte[] INDEX_MAGIC = { 'R', 'A', 'Z', 'I', 'P', 'I', 'N', 'D', 'E', 'X' };

    public static void main(String[] args) {
        if (args.length < 1) {
            printHelp();
            return;
        }
        String op = args[0].toLowerCase();

        try {
            switch (op) {
                case "-c": // 压缩操作
                    if (args.length < 2 || args.length > 3) {
                        System.err.println("Usage: java RAZF -c input [output]");
                        printHelp();
                        return;
                    }
                    String cinput = args[1];
                    // 输出文件名默认为输入文件名加.rz后缀
                    String coutput = (args.length == 3) ? args[2] : getOutputFileName(cinput, "compress");
                    compress(new File(cinput), new File(coutput));
                    System.out.println("Compression done: " + coutput);
                    break;
                case "-d": // 解压操作
                    if (args.length == 2 || args.length == 3) {
                        // 全文件解压
                        String dinput = args[1];
                        String doutput = (args.length == 3) ? args[2] : getOutputFileName(dinput, "decompress");
                        decompress(new File(dinput), new File(doutput));
                        System.out.println("Full decompression done: " + doutput);
                        break;
                    } else if (args.length == 4 || args.length == 5) {
                        // 部分解压
                        String dinput = args[1];
                        long pos = Long.parseLong(args[2]);
                        int len = Integer.parseInt(args[3]);
                        String doutput = (args.length == 5) ? args[4] : getOutputFileName(dinput, "decompress");
                        decompress(new File(dinput), new File(doutput), pos, len);
                        System.out.println("Partial decompression done: " + doutput);
                        break;
                    } else {
                        System.err.println("Usage: java RAZF -d input [pos len] [output]");
                        printHelp();
                        return;
                    }
                case "-l": // 列出压缩文件信息
                    if (args.length != 2) {
                        System.err.println("Usage: java RAZF -l input");
                        printHelp();
                        return;
                    }
                    listInfo(new File(args[1]));
                    break;
                case "-h": // 帮助
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
     * 全文件解压（块遍历解压实现）
     */
    public static void decompress(File input, File output) throws IOException {
        // 读取索引偏移数组
        long[] blockOffsets = readIndex(input);
        if (blockOffsets == null || blockOffsets.length == 0)
            throw new IOException("No index found in RAZF file");
        int blockSize;
        try (InputStream in = new BufferedInputStream(new FileInputStream(input))) {
            blockSize = parseHeader(in); // 解析头部，获得块大小
        }
        long totalRawSize = readOriginalSize(input); // 读取原始数据总大小

        try (RandomAccessFile raf = new RandomAccessFile(input, "r");
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
            int blockCount = blockOffsets.length;
            long writtenBytes = 0;

            for (int blk = 0; blk < blockCount; blk++) {
                long startOffset = blockOffsets[blk];
                long nextOffset = (blk + 1 < blockOffsets.length)
                        ? blockOffsets[blk + 1]
                        : (raf.length() - getIndexSectionLength(raf));
                int compSize = (int) (nextOffset - startOffset);

                // 读取压缩块数据
                raf.seek(startOffset);
                byte[] compData = new byte[compSize];
                raf.readFully(compData);

                // 使用Inflater进行解压
                Inflater inflater = new Inflater(true); // GZIP _nowrap
                inflater.setInput(compData);
                byte[] outBuf = new byte[Math.max(blockSize, BUFFER_SIZE)];
                int totalDecompThisBlock = 0;
                ByteArrayOutputStream baos = new ByteArrayOutputStream(blockSize);

                try {
                    while (!inflater.finished()) {
                        int n = inflater.inflate(outBuf);
                        if (n == 0) {
                            if (inflater.finished()) break;
                            if (inflater.needsDictionary()) throw new IOException("Inflater needs dictionary");
                            break;
                        }
                        baos.write(outBuf, 0, n);
                        totalDecompThisBlock += n;
                        if (totalDecompThisBlock > blockSize * 2) break; // 防止异常数据
                    }
                } catch (DataFormatException ex) {
                    throw new IOException("Data format error in inflate", ex);
                } finally {
                    inflater.end();
                }
                byte[] blockDecomp = baos.toByteArray();

                // 处理最后一块可能不足一块完整大小
                int toWrite = blockDecomp.length;
                if (writtenBytes + toWrite > totalRawSize)
                    toWrite = (int) (totalRawSize - writtenBytes);
                if (toWrite > 0) {
                    out.write(blockDecomp, 0, toWrite);
                    writtenBytes += toWrite;
                }
            }
        }
    }

    /**
     * 按部分内容解压（从指定位置开始，读取长度）
     */
    public static void decompress(File input, File output, long position, int length) throws IOException {
        if (length <= 0) throw new IllegalArgumentException("Length must be positive");
        long[] blockOffsets = readIndex(input);
        if (blockOffsets == null || blockOffsets.length == 0)
            throw new IOException("No index found in RAZF file");

        int blockSize;
        try (InputStream in = new BufferedInputStream(new FileInputStream(input))) {
            blockSize = parseHeader(in);
        }

        long originalSize = readOriginalSize(input);
        if (position < 0 || position >= originalSize) {
            throw new IllegalArgumentException("Position out of bounds");
        }
        if (position + length > originalSize) {
            length = (int) (originalSize - position); // 调整避免越界
        }

        try (RandomAccessFile raf = new RandomAccessFile(input, "r");
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {

            long remaining = length;
            long currentPos = position;
            int startBlock = (int) (position / blockSize);
            int endBlock = (int) ((position + length - 1) / blockSize);

            for (int blk = startBlock; blk <= endBlock; blk++) {
                long fileOffset = blockOffsets[blk];
                long nextOffset = (blk + 1 < blockOffsets.length)
                        ? blockOffsets[blk + 1]
                        : (raf.length() - getIndexSectionLength(raf));
                int csize = (int) (nextOffset - fileOffset);

                // 读取压缩块
                raf.seek(fileOffset);
                byte[] compData = new byte[csize];
                raf.readFully(compData);

                Inflater inflater = new Inflater(true);
                inflater.setInput(compData);
                ByteArrayOutputStream baos = new ByteArrayOutputStream(blockSize);
                byte[] tmpOutBuf = new byte[BUFFER_SIZE];
                int totalDecompressed = 0;

                try {
                    while (!inflater.finished()) {
                        int n = inflater.inflate(tmpOutBuf);
                        if (n == 0) {
                            if (inflater.finished()) break;
                            if (inflater.needsDictionary()) throw new IOException("Inflater needs dictionary");
                            break;
                        }
                        baos.write(tmpOutBuf, 0, n);
                        totalDecompressed += n;
                        if (totalDecompressed > blockSize * 2) break; // 防异常
                    }
                } catch (DataFormatException ex) {
                    throw new IOException("Data format exception during inflate", ex);
                } finally {
                    inflater.end();
                }

                byte[] decompressedBytes = baos.toByteArray();
                long blockStartOrig = (long) blk * (long) blockSize;
                long blockEndOrig = blockStartOrig + decompressedBytes.length;

                // 如果当前块包含待解内容区间
                long startCopy = Math.max(currentPos, blockStartOrig);
                long endCopy = Math.min(position + length, blockEndOrig);

                if (endCopy > startCopy) {
                    int offsetInBlock = (int) (startCopy - blockStartOrig);
                    int bytesToWrite = (int) (endCopy - startCopy);
                    out.write(decompressedBytes, offsetInBlock, bytesToWrite);
                    remaining -= bytesToWrite;
                    currentPos += bytesToWrite;
                    if (remaining <= 0) break;
                }
            }
        }
    }

    /**
     * 获取索引部分长度（尾部扫描找到索引位置）
     */
    private static long getIndexSectionLength(RandomAccessFile raf) throws IOException {
        long fileLen = raf.length();
        long searchLen = Math.min(fileLen, 20 * 1024); // 搜索尾部20KB
        byte[] tail = new byte[(int) searchLen];
        raf.seek(fileLen - searchLen);
        raf.readFully(tail);

        int ix = -1;
        outer:
        for (int i = tail.length - 10; i >= 0; i--) {
            for (int k = 0; k < 10; k++) {
                if (tail[i + k] != INDEX_MAGIC[k]) continue outer;
            }
            ix = i;
            break;
        }
        if (ix < 0)
            return 0; // 未找到索引

        int pos = ix + 10; // 索引magic后面位置
        if (pos + 4 > tail.length)
            return 0;

        int count = ((tail[pos] & 0xff) | ((tail[pos + 1] & 0xff) << 8)
                | ((tail[pos + 2] & 0xff) << 16) | ((tail[pos + 3] & 0xff) << 24));
        // 索引前的最后一部分大概是索引长度，避免越界
        long idxLen = 10 /*MAGIC*/ + 4 /*count*/ + ((long) count) * 8L + 8 /*CRC32+origlen*/;
        return idxLen;
    }

    /**
     * 1. 块式压缩
     * 采用块压缩，输出index索引等信息
     */
    public static void compress(InputStream in, OutputStream out, int blockSize) throws IOException {
        List<Long> blockOffsets = new ArrayList<>(); // 记录每块起始偏移
        ByteCounterOutputStream bout = new ByteCounterOutputStream(out);
        writeHeader(bout, blockSize); // 写入GZIP头+扩展信息

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        CRC32 crc = new CRC32();

        byte[] inBuf = new byte[blockSize];
        byte[] outBuf = new byte[BUFFER_SIZE];

        long totalRaw = 0;
        int len;
        long fileOffset = bout.getCount();

        while ((len = in.read(inBuf)) > 0) {
            // 记录当前块起始偏移
            blockOffsets.add(fileOffset);
            crc.update(inBuf, 0, len);
            totalRaw += len;

            deflater.reset();
            deflater.setInput(inBuf, 0, len);
            deflater.finish();

            // 压缩数据块
            while (!deflater.finished()) {
                int compressedLen = deflater.deflate(outBuf);
                if (compressedLen > 0) {
                    bout.write(outBuf, 0, compressedLen);
                    fileOffset += compressedLen;
                }
            }
        }
        deflater.end();

        // 追加 CRC和原始总大小信息（在文件尾）
        writeIntLE(bout, (int) crc.getValue()); // CRC
        writeIntLE(bout, (int) totalRaw); // uncompressed size

        // 写入索引魔数和块偏移数组
        bout.write(INDEX_MAGIC);
        writeIntLE(bout, blockOffsets.size());
        for (Long off : blockOffsets)
            writeLongLE(bout, off);

        bout.flush();
    }

    /**
     * 根据文件名压缩（调用块压缩）
     */
    public static void compress(File input, File output) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(input));
             OutputStream out = new BufferedOutputStream(new FileOutputStream(output))) {
            compress(in, out, DEFAULT_BLOCK_SIZE);
        }
    }

    /**
     * 读取索引偏移数组
     */
    public static long[] readIndex(File input) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            long flen = raf.length();
            long maxBack = Math.min(20 * 1024, flen);
            byte[] tail = new byte[(int) maxBack];
            raf.seek(flen - tail.length);
            raf.readFully(tail);

            int ix = -1;
            // 搜索索引magic
            outer:
            for (int i = tail.length - 10; i >= 0; i--) {
                for (int k = 0; k < 10; k++) {
                    if (tail[i + k] != INDEX_MAGIC[k]) continue outer;
                }
                ix = i;
                break;
            }
            if (ix < 0)
                throw new IOException("Block offset index not found in file tail");

            int pos = ix + 10; // magic后位置
            if (pos + 4 > tail.length)
                throw new EOFException();

            int count = ((tail[pos] & 0xff) | ((tail[pos + 1] & 0xff) << 8)
                    | ((tail[pos + 2] & 0xff) << 16) | ((tail[pos + 3] & 0xff) << 24));
            pos += 4;
            if (pos + count * 8 > tail.length)
                throw new EOFException();

            long[] offs = new long[count];
            for (int i = 0; i < count; i++) {
                long off = 0;
                for (int j = 0; j < 8; j++) {
                    off |= ((long) (tail[pos++] & 0xff)) << (8 * j);
                }
                offs[i] = off;
            }
            return offs;
        }
    }

    /**
     * 打印帮助信息
     */
    public static void printHelp() {
        System.out.println(
            "Usage:   java RAZF [options] [file] ...\n\n"
            + "Options:\n"
            + "  -c input [output]            compress input file\n"
            + "  -d input [output]            decompress ENTIRE input file\n"
            + "  -d input pos len [output]    decompress input file from pos for len bytes\n"
            + "  -l input                     list info of input file\n"
            + "  -h                           show this help\n"
        );
    }

    /**
     * 根据操作类型生成输出文件名
     */
    public static String getOutputFileName(String inputFileName, String op) {
        File inputFile = new File(inputFileName);
        String parent = inputFile.getParent();
        String name = inputFile.getName();
        String outputName;
        if ("compress".equalsIgnoreCase(op)) {
            if (name.toLowerCase().endsWith(".rz"))
                outputName = name;
            else
                outputName = name + ".rz";
        } else if ("decompress".equalsIgnoreCase(op)) {
            if (name.toLowerCase().endsWith(".rz")) {
                outputName = name.substring(0, name.length() - 3);
                if (outputName.isEmpty()) outputName = "output";
            } else {
                outputName = name + ".decompressed";
            }
        } else {
            return null;
        }
        return parent != null ? new File(parent, outputName).getPath() : outputName;
    }

    /**
     * 读取压缩文件中的原始数据大小（在尾部存储）
     */
    private static long readOriginalSize(File f) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long fileLength = raf.length();
            // 搜索尾部索引信息
            long indexPos = -1;
            long searchMax = Math.min(fileLength, 20 * 1024);
            byte[] tail = new byte[(int) searchMax];
            raf.seek(fileLength - searchMax);
            raf.readFully(tail);

            int ix = -1;
            outer:
            for (int i = tail.length - 10; i >= 0; i--) {
                for (int k = 0; k < 10; k++) {
                    if (tail[i + k] != INDEX_MAGIC[k]) continue outer;
                }
                ix = i;
                break;
            }

            if (ix >= 0) {
                indexPos = fileLength - tail.length + ix;
            } else {
                indexPos = fileLength;
            }

            long sizeblockPos = indexPos - 8; // 原始大小存于index尾部的8字节前
            if (sizeblockPos < 0)
                throw new IOException("File structure error: index/index marker not found or file too small.");

            raf.seek(sizeblockPos + 4); // crc32后面4字节存放原size
            int v0 = raf.read();
            int v1 = raf.read();
            int v2 = raf.read();
            int v3 = raf.read();
            if (v3 < 0)
                throw new IOException("File truncated before uncompressed size field");
            long rawSize = ((v0 & 0xffL))
                         | ((v1 & 0xffL) << 8)
                         | ((v2 & 0xffL) << 16)
                         | ((v3 & 0xffL) << 24);
            return rawSize;
        }
    }

    /**
     * 打印压缩文件信息
     */
    public static void listInfo(File inputFile) throws IOException {
        try (InputStream fis = new FileInputStream(inputFile)) {
            int blockSize = parseHeader(fis); // 解析头部

            long compressedFileSize = inputFile.length(); // 文件大小
            long originalFileSize = -1;
            try {
                originalFileSize = readOriginalSize(inputFile);
            } catch (Exception ex) {
                originalFileSize = -1; // 无法读取
            }

            System.out.println("RAZF Compressed File Info:");
            System.out.println("  Block Size: " + blockSize);
            if (originalFileSize >= 0)
                System.out.println("  Original File Size: " + originalFileSize + " bytes");
            else
                System.out.println("  Original File Size: (unknown)");

            System.out.println("  Compressed File Size: " + compressedFileSize + " bytes");
            try {
                long[] offs = readIndex(inputFile);
                System.out.println("  Block Count: " + offs.length);
                System.out.print("  Data Block Offsets: ");
                for (int i = 0; i < offs.length; i++) {
                    System.out.print(offs[i]);
                    if (i < offs.length - 1)
                        System.out.print(", ");
                }
                System.out.println();
            } catch (Exception ex) {
                System.out.println("  Data Block Offsets: Index not found or parse error.");
            }
        }
    }

    /**
     * 写入GZIP头部信息（包括扩展块，存放块大小）
     */
    private static void writeHeader(OutputStream out, int blockSize) throws IOException {
        out.write(GZIP_ID1);
        out.write(GZIP_ID2);
        out.write(GZIP_CM);
        out.write(GZIP_FLG);
        writeIntLE(out, 0); // mtime（空）
        out.write(0); // extra flags
        out.write(GZIP_OS);
        writeShortLE(out, 8); // extra field length = 8
        // 扩展字段：存块大小
        out.write('R'); out.write('A');
        writeShortLE(out, 4); // 4字节的类型
        writeIntLE(out, blockSize); // 块大小存储
    }

    /**
     * 解析GZIP头，返回块大小
     */
    public static int parseHeader(InputStream in) throws IOException {
        byte[] buf = new byte[GZIP_HEADER_SIZE];
        int got = in.read(buf);
        if (got != GZIP_HEADER_SIZE)
            throw new IOException("File too short");
        if (buf[0] != GZIP_ID1 || buf[1] != GZIP_ID2 || buf[2] != GZIP_CM)
            throw new IOException("Not a valid GZIP/RAZF file");
        if ((buf[3] & GZIP_FLG) != GZIP_FLG)
            throw new IOException("No GZIP FEXTRA flag (not RAZF)");

        int xlen = readShortLE(in);
        if (xlen < 8)
            throw new IOException("No RAZF extra");
        byte[] extra = new byte[xlen];
        int r = in.read(extra);
        if (r != xlen)
            throw new IOException("Unexpected EOF reading extra");

        // 解析扩展块
        for (int pos = 0; pos + 4 <= xlen;) {
            byte s1 = extra[pos], s2 = extra[pos + 1];
            int slen = (extra[pos + 2] & 0xff) | ((extra[pos + 3] & 0xff) << 8);
            if (pos + 4 + slen > xlen)
                break;
            if (s1 == 'R' && s2 == 'A' && slen == 4) {
                int b0 = extra[pos + 4] & 0xff;
                int b1 = extra[pos + 5] & 0xff;
                int b2 = extra[pos + 6] & 0xff;
                int b3 = extra[pos + 7] & 0xff;
                return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            }
            pos += 4 + slen;
        }
        throw new IOException("RAZF block size tag missing in extra field");
    }

    /**
     * ByteCounterOutputStream - 统计输出字节数
     */
    public static class ByteCounterOutputStream extends FilterOutputStream {
        private long count = 0; // 统计字节数

        public ByteCounterOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            count += len;
        }

        public long getCount() {
            return count;
        }
    }

    // 以下是辅助方法：写入/读取LE字节序的整数和长整数

    private static void writeShortLE(OutputStream o, int v) throws IOException {
        o.write(v & 0xff);
        o.write((v >>> 8) & 0xff);
    }

    private static void writeIntLE(OutputStream o, int v) throws IOException {
        o.write(v & 0xff);
        o.write((v >>> 8) & 0xff);
        o.write((v >>> 16) & 0xff);
        o.write((v >>> 24) & 0xff);
    }

    private static void writeLongLE(OutputStream o, long v) throws IOException {
        for (int i = 0; i < 8; ++i)
            o.write((int) (v >>> (8 * i)) & 0xff);
    }

    private static int readShortLE(InputStream o) throws IOException {
        int b0 = o.read();
        int b1 = o.read();
        if ((b0 | b1) < 0)
            throw new EOFException();
        return ((b1 & 0xff) << 8) | (b0 & 0xff);
    }

    private static int readIntLE(InputStream o) throws IOException {
        int b0 = o.read();
        int b1 = o.read();
        int b2 = o.read();
        int b3 = o.read();
        if ((b0 | b1 | b2 | b3) < 0)
            throw new IOException("Unexpected EOF");
        return (b0 & 0xff) | ((b1 & 0xff) << 8) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 24);
    }

    private static long readLongLE(InputStream o) throws IOException {
        long r = 0;
        for (int i = 0; i < 8; ++i) {
            int b = o.read();
            if (b < 0) throw new EOFException();
            r |= ((long) b & 0xff) << (8 * i);
        }
        return r;
    }
}