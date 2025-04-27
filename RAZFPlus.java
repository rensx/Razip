import org.apache.commons.cli.*;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.zip.*;


/**
 * RAZFPlus - 一种支持块压缩的文件格式，具有索引信息，快速部分解压
 * Reference: https://github.com/lh3/samtools
 * 命令行处理：使用了 Apache Commons CLI 库，用户可通过参数 -b 指定块大小，-L 指定压缩等级（0-9）。
 * 压缩多线程：使用线程池异步压缩多个块以提速，同时写出保持顺序。块异步压缩结果收集，按顺序写入文件。
 * 解压多线程：解压多个块并发处理，但因随机访问文件可能线程安全问题，读文件操作同步，写输出文件保证顺序。
 * 文件锁：压缩和解压都对输出文件加了文件锁，防止多进程并发写文件问题。
 * 异常与容错：读取索引和解压块均进行了异常捕获，规范异常信息输出，并保证数据完整性检查。
 * 性能优化：使用较大缓冲区（256KB），循环读取完整块保证I/O一次多数据。
 * 安全性：解压部分限制最大解压大小，防止异常压缩数据导致内存暴涨。
 * CRC32校验：压缩时计算 CRC32，写入到文件尾部，可后续扩展验证；当前代码未额外实现解压时的CRC校验，可根据需求二次扩展。
 */
public class RAZFPlus {

    /* --- 常量定义 --- */
    public static final int DEFAULT_BLOCK_SIZE = 64 * 1024; // 64 KB
    public static final int BUFFER_SIZE = 256 * 1024; // 256 KB缓冲区，较大减少磁盘访问
    public static final byte[] MAGIC = {'R', 'A', 'Z', 'F'}; // 文件标志 Header

    public static final int GZIP_HEADER_SIZE = 10; // GZIP头长度
    public static final byte GZIP_ID1 = 0x1f;
    public static final byte GZIP_ID2 = (byte) 0x8b;
    public static final byte GZIP_CM = 8; // 压缩方法：Deflate
    public static final byte GZIP_FLG = 4; // 说明含有FEXTRA字段
    public static final byte GZIP_OS = 3;  // 操作系统类型（Unix）

    // 索引部分MAGIC
    public static final byte[] INDEX_MAGIC = {'R', 'A', 'Z', 'I', 'P', 'I', 'N', 'D', 'E', 'X'};

    /* --- 日志辅助，仅打印stderr --- */
    private static void log(String msg) {
        System.err.println("[RAZFPlus] " + msg);
    }

    /**
     * Entry主方法，采用Apache Commons CLI解析参数，支持多参数配置。
     */
    public static void main(String[] args) {
        Options options = new Options();

        Option compressOpt = Option.builder("c")
                .desc("compress input file")
                .hasArg()
                .argName("input")
                .build();

        Option decompressOpt = Option.builder("d")
                .desc("decompress input file")
                .hasArgs()
                .argName("input [pos len] [output]")
                .optionalArg(true)
                .build();

        Option listOpt = Option.builder("l")
                .desc("list info of input file")
                .hasArg()
                .argName("input")
                .build();

        Option blockSizeOpt = Option.builder("b")
                .desc("block size for compression (bytes), default 65536")
                .hasArg()
                .argName("blockSize")
                .build();

        Option levelOpt = Option.builder("L")
                .desc("compression level [0-9], default 6")
                .hasArg()
                .argName("level")
                .build();

        Option helpOpt = new Option("h", "help", false, "show help");

        options.addOption(compressOpt);
        options.addOption(decompressOpt);
        options.addOption(listOpt);
        options.addOption(blockSizeOpt);
        options.addOption(levelOpt);
        options.addOption(helpOpt);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args, true);

            if (cmd.hasOption("h") || args.length == 0) {
                formatter.printHelp("java RAZFPlus [options]", options);
                return;
            }

            int blockSize = DEFAULT_BLOCK_SIZE;
            int compressionLevel = Deflater.DEFAULT_COMPRESSION;

            if (cmd.hasOption("b")) {
                try {
                    blockSize = Integer.parseInt(cmd.getOptionValue("b"));
                    if (blockSize < 1024 || blockSize > 10 * 1024 * 1024) {
                        throw new IllegalArgumentException("Block size out of valid range (1KB - 10MB).");
                    }
                } catch (Exception e) {
                    log("Invalid blockSize parameter: " + e.getMessage());
                    return;
                }
            }

            if (cmd.hasOption("L")) {
                try {
                    compressionLevel = Integer.parseInt(cmd.getOptionValue("L"));
                    if (compressionLevel < 0 || compressionLevel > 9) {
                        throw new IllegalArgumentException("Compression level must be between 0 and 9.");
                    }
                } catch (Exception e) {
                    log("Invalid compression level parameter: " + e.getMessage());
                    return;
                }
            }

            // 解析顺序优先级：compress, decompress, list (只能选一个操作)
            if (cmd.hasOption("c")) {
                String[] vals = cmd.getOptionValues("c");
                if (vals == null || vals.length == 0) {
                    log("Compression input file is missing.");
                    formatter.printHelp("java RAZFPlus -c <input> [output]", options);
                    return;
                }
                String input = vals[0];
                String output = (vals.length >= 2) ? vals[1] : getOutputFileName(input, "compress");
                compress(new File(input), new File(output), blockSize, compressionLevel);
                System.out.println("Compression done: " + output);

            } else if (cmd.hasOption("d")) {
                String[] vals = cmd.getOptionValues("d");
                if (vals == null || vals.length < 1) {
                    log("Decompression input file is missing.");
                    formatter.printHelp("java RAZFPlus -d <input> [pos len] [output]", options);
                    return;
                }

                File inputFile = new File(vals[0]);

                if (vals.length == 1 || vals.length == 2) {
                    // 全文件解压
                    String output = (vals.length == 2) ? vals[1] : getOutputFileName(vals[0], "decompress");
                    decompress(inputFile, new File(output));
                    System.out.println("Full decompression done: " + output);

                } else if (vals.length == 3 || vals.length == 4) {
                    // 部分解压： input pos len [output]
                    try {
                        long pos = Long.parseLong(vals[1]);
                        int len = Integer.parseInt(vals[2]);
                        String output = (vals.length == 4) ? vals[3] : getOutputFileName(vals[0], "decompress");
                        decompress(inputFile, new File(output), pos, len);
                        System.out.println("Partial decompression done: " + output);
                    } catch (NumberFormatException e) {
                        log("Invalid pos or len parameter for partial decompression.");
                        formatter.printHelp("java RAZFPlus -d <input> [pos len] [output]", options);
                    }
                } else {
                    log("Invalid decompression parameters.");
                    formatter.printHelp("java RAZFPlus -d <input> [pos len] [output]", options);
                }

            } else if (cmd.hasOption("l")) {
                String inputFile = cmd.getOptionValue("l");
                listInfo(new File(inputFile));
            } else {
                log("No valid operation specified.");
                formatter.printHelp("java RAZFPlus [options]", options);
            }

        } catch (ParseException e) {
            log("Failed to parse command line arguments: " + e.getMessage());
        } catch (Exception e) {
            log("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /* ================== 压缩功能 ================== */

    /**
     * 对文件进行块压缩，支持多线程压缩提升性能。
     *
     * @param inputFile       待压缩文件
     * @param outputFile      压缩结果文件
     * @param blockSize       每个压缩块大小
     * @param compressionLevel 压缩级别（0-9）
     *
     * @throws IOException IO异常
     */
    public static void compress(File inputFile, File outputFile, int blockSize, int compressionLevel) throws IOException {
        log("Start compress: blockSize=" + blockSize + " compressionLevel=" + compressionLevel);

        // 加锁防止多进程操作文件冲突
        try (RandomAccessFile rafLock = new RandomAccessFile(outputFile, "rw");
             FileChannel channel = rafLock.getChannel();
             FileLock lock = channel.lock()) {
            // 打开输入流
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {

                ByteCounterOutputStream bout = new ByteCounterOutputStream(out);

                writeHeader(bout, blockSize);

                CRC32 crc = new CRC32();

                // 读取块数据并行压缩方案：
                // 生产者读取数据块，放入队列
                // 多线程压缩线程池，异步压缩数据块
                // 按序写入文件（保持索引顺序）

                ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

                List<Future<BlockCompressed>> compressedBlocks = new ArrayList<>();

                byte[] readBuffer = new byte[blockSize];
                int readLen;
                long totalRaw = 0;
                int blockIndex = 0;

                // 生产任务并提交线程池
                while ((readLen = readBlock(in, readBuffer, blockSize)) > 0) {
                    final byte[] dataBlock = new byte[readLen];
                    System.arraycopy(readBuffer, 0, dataBlock, 0, readLen);
                    final int idx = blockIndex++;
                    totalRaw += readLen;
                    crc.update(dataBlock);

                    // 异步压缩任务
                    Future<BlockCompressed> future = executor.submit(() -> compressBlock(dataBlock, compressionLevel, idx));
                    compressedBlocks.add(future);
                }

                executor.shutdown();

                // 写入块偏移索引
                List<Long> blockOffsets = new ArrayList<>();
                long offset = bout.getCount();

                // 获取压缩块结果，按顺序写入
                for (Future<BlockCompressed> f : compressedBlocks) {
                    BlockCompressed bc;
                    try {
                        bc = f.get(); // 阻塞等待完成
                    } catch (ExecutionException e) {
                        throw new IOException("Compression thread failed: " + e.getCause(), e);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Compression interrupted");
                    }
                    blockOffsets.add(offset);
                    bout.write(bc.compressedData);
                    offset += bc.compressedData.length;
                }

                // 等待线程池彻底关闭
                if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                    log("Compression executor forced shutdown.");
                }

                // 写入CRC32和原始大小(4字节int限制64MB，考虑改为long)
                writeIntLE(bout, (int) crc.getValue());
                writeLongLE(bout, totalRaw);

                // 写入索引结构
                bout.write(INDEX_MAGIC);
                writeIntLE(bout, blockOffsets.size());
                for (Long off : blockOffsets) {
                    writeLongLE(bout, off);
                }

                bout.flush();
                log("Compression complete. Blocks: " + blockOffsets.size());

            }

        } catch (IOException e) {
            log("File lock or IO error during compression: " + e.getMessage());
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log("Compression interrupted.");
            throw new IOException("Compression interrupted.");
        }
    }

    /**
     * 读取一块数据，支持块不足但不为0的情况。
     *
     * @param in        输入流
     * @param buffer    读取缓冲区，长度通常为blockSize
     * @param blockSize 块大小
     * @return 实际读取字节数
     * @throws IOException
     */
    private static int readBlock(InputStream in, byte[] buffer, int blockSize) throws IOException {
        int offset = 0;
        while (offset < blockSize) {
            int readLen = in.read(buffer, offset, blockSize - offset);
            if (readLen < 0) break;
            offset += readLen;
        }
        return offset;
    }

    /**
     * 压缩单个数据块（无头部，Deflate nowrap）
     *
     * @param data             待压缩块数据
     * @param compressionLevel 压缩等级
     * @param index            块索引，用于调试
     * @return 压缩结果与索引
     * @throws IOException
     */
    private static BlockCompressed compressBlock(byte[] data, int compressionLevel, int index) throws IOException {
        Deflater deflater = new Deflater(compressionLevel, true);
        deflater.setInput(data);
        deflater.finish();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);

        byte[] buf = new byte[BUFFER_SIZE];
        while (!deflater.finished()) {
            int len = deflater.deflate(buf);
            if (len > 0) {
                baos.write(buf, 0, len);
            } else {
                break;
            }
        }

        deflater.end();
        return new BlockCompressed(index, baos.toByteArray());
    }

    /**
     * 存储单个压缩块结果及块号
     */
    private static class BlockCompressed {
        int blockIndex;
        byte[] compressedData;

        BlockCompressed(int blockIndex, byte[] compressedData) {
            this.blockIndex = blockIndex;
            this.compressedData = compressedData;
        }
    }

    /* ================== 解压功能 ================== */

    /**
     * 全文件解压，使用多线程并保持顺序写出
     *
     * @param inputFile  RAZFPlus压缩文件
     * @param outputFile 解压输出文件
     * @throws IOException
     */
    public static void decompress(File inputFile, File outputFile) throws IOException {
        log("Start full decompression for " + inputFile.getPath());

        // 加文件锁避免并发写入冲突
        try (RandomAccessFile rafLock = new RandomAccessFile(outputFile, "rw");
             FileChannel channel = rafLock.getChannel();
             FileLock lock = channel.lock()) {

            long[] blockOffsets = safelyReadIndex(inputFile);
            if (blockOffsets.length == 0) {
                throw new IOException("No block index found.");
            }

            // 读取块大小
            int blockSize;
            try (InputStream is = new BufferedInputStream(new FileInputStream(inputFile))) {
                blockSize = parseHeader(is);
            }

            long originalSize = readOriginalSize(inputFile);
            if (originalSize < 0) originalSize = Long.MAX_VALUE; // 防空

            // 多线程解压
            ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

            try (RandomAccessFile rafIn = new RandomAccessFile(inputFile, "r");
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {

                // 提交解压任务，保存Future，保证顺序写输出
                List<Future<BlockDecompressed>> results = new ArrayList<>();
                int blockCount = blockOffsets.length;

                for (int i = 0; i < blockCount; i++) {
                    final int blockIdx = i;
                    Future<BlockDecompressed> future = executor.submit(() -> decompressBlock(rafIn, blockOffsets, blockIdx, blockSize, inputFile.length()));
                    results.add(future);
                }

                long writtenBytes = 0;

                for (Future<BlockDecompressed> f : results) {
                    BlockDecompressed decompressedBlock;
                    try {
                        decompressedBlock = f.get();
                    } catch (ExecutionException e) {
                        throw new IOException("Error decompressing block: " + e.getCause(), e);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Decompression interrupted.");
                    }

                    // 防越界写入
                    int toWrite = decompressedBlock.data.length;
                    if (writtenBytes + toWrite > originalSize) {
                        toWrite = (int) (originalSize - writtenBytes);
                    }
                    if(toWrite > 0) {
                        out.write(decompressedBlock.data, 0, toWrite);
                        writtenBytes += toWrite;
                    }
                    if(writtenBytes >= originalSize) break;
                }

                out.flush();
            } finally {
                executor.shutdownNow();
            }
        } catch (IOException e) {
            log("Decompression IO error or lock error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 部分解压，从position开始，长度length字节。
     *
     * @param inputFile  RAZFPlus压缩文件
     * @param outputFile 输出文件
     * @param position   解压起始位置（原始未压缩文件偏移）
     * @param length     解压长度
     * @throws IOException
     */
    public static void decompress(File inputFile, File outputFile, long position, int length) throws IOException {
        log("Start partial decompression for " + inputFile.getPath() + " from position=" + position + ", length=" + length);

        if (length <= 0)
            throw new IllegalArgumentException("Length must be positive.");

        // 加锁防止文件冲突
        try (RandomAccessFile rafLock = new RandomAccessFile(outputFile, "rw");
             FileChannel channel = rafLock.getChannel();
             FileLock lock = channel.lock()) {

            long[] blockOffsets = safelyReadIndex(inputFile);
            if (blockOffsets.length == 0)
                throw new IOException("No block index found.");

            int blockSize;
            try (InputStream is = new BufferedInputStream(new FileInputStream(inputFile))) {
                blockSize = parseHeader(is);
            }

            long originalSize = readOriginalSize(inputFile);
            if (position < 0 || position >= originalSize) {
                throw new IllegalArgumentException("Position out of bounds. Original size=" + originalSize);
            }
            if (position + length > originalSize) {
                length = (int) (originalSize - position); // 调整避免越界
            }

            try (RandomAccessFile rafIn = new RandomAccessFile(inputFile, "r");
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {

                int startBlock = (int) (position / blockSize);
                int endBlock = (int) ((position + length - 1) / blockSize);

                long stillToWrite = length;
                long currentPos = position;

                for (int blk = startBlock; blk <= endBlock; blk++) {

                    BlockDecompressed decBlock = decompressBlock(rafIn, blockOffsets, blk, blockSize, inputFile.length());

                    long blockStartOrig = (long) blk * blockSize;         // 当前块原始数据偏移
                    long blockEndOrig = blockStartOrig + decBlock.data.length;

                    long startCopy = Math.max(currentPos, blockStartOrig);
                    long endCopy = Math.min(position + length, blockEndOrig);

                    if (endCopy > startCopy) {
                        int offsetInBlock = (int) (startCopy - blockStartOrig);
                        int bytesToWrite = (int) (endCopy - startCopy);
                        out.write(decBlock.data, offsetInBlock, bytesToWrite);
                        stillToWrite -= bytesToWrite;
                        currentPos += bytesToWrite;
                        if (stillToWrite <= 0) break;
                    }
                }

                out.flush();
            }
        }
    }

    /**
     * 解压单块数据，返回解压的原始数据。
     * 采用外围同步，保证RandomAccessFile读取安全，多线程调用时通过同步块避免竞争。
     *
     * @param raf          RandomAccessFile对象，已打开
     * @param blockOffsets 块偏移数组
     * @param blockIndex   当前块索引
     * @param blockSize    块大小
     * @param fileLength   文件总长度
     * @return 解压数据块
     * @throws IOException
     */
    private static BlockDecompressed decompressBlock(RandomAccessFile raf, long[] blockOffsets, int blockIndex, int blockSize, long fileLength) throws IOException {
        byte[] compData;
        synchronized (raf) {
            long startOffset = blockOffsets[blockIndex];
            long nextOffset = (blockIndex + 1 < blockOffsets.length) ? blockOffsets[blockIndex + 1] : (fileLength - getIndexSectionLength(raf));
            int csize = (int) (nextOffset - startOffset);

            if (csize <= 0) throw new IOException("Invalid compressed block size: " + csize);

            raf.seek(startOffset);
            compData = new byte[csize];
            raf.readFully(compData);
        }

        Inflater inflater = new Inflater(true); // no wrap because raw DEFLATE blocks
        inflater.setInput(compData);

        ByteArrayOutputStream baos = new ByteArrayOutputStream(blockSize);
        byte[] tmpBuf = new byte[BUFFER_SIZE];

        try {
            int totalDecomp = 0;
            while (!inflater.finished()) {
                int n = inflater.inflate(tmpBuf);
                if (n == 0) {
                    if (inflater.finished()) break;
                    if (inflater.needsDictionary())
                        throw new IOException("Inflater needs dictionary");
                    break;
                }
                baos.write(tmpBuf, 0, n);
                totalDecomp += n;
                if (totalDecomp > blockSize * 10)  // 防止异常大数据爆炸
                    throw new IOException("Decompressed data too large or corrupted block data.");
            }
        } catch (DataFormatException e) {
            throw new IOException("Data format error during inflate", e);
        } finally {
            inflater.end();
        }

        return new BlockDecompressed(blockIndex, baos.toByteArray());
    }

    /**
     * 存储解压后的块数据和其索引。
     */
    private static class BlockDecompressed {
        int blockIndex;
        byte[] data;

        BlockDecompressed(int blockIndex, byte[] data) {
            this.blockIndex = blockIndex;
            this.data = data;
        }
    }

    /* ================== 索引读取及辅助 ================== */

    /**
     * 安全读取索引，捕获异常并打印。
     */
    private static long[] safelyReadIndex(File input) throws IOException {
        try {
            return readIndex(input);
        } catch (Exception e) {
            log("Error reading index: " + e.getMessage());
            throw e;
        }
    }

    /**
     * 读取索引偏移数组。
     *
     * @param input 文件名
     * @return 长整型数组，块起始偏移
     * @throws IOException 读取异常
     */
    public static long[] readIndex(File input) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(input, "r")) {
            long fileLength = raf.length();
            long maxBack = Math.min(20L * 1024L, fileLength);
            byte[] tail = new byte[(int) maxBack];
            raf.seek(fileLength - maxBack);
            raf.readFully(tail);

            int indexPos = -1;
            outer:
            for (int i = tail.length - INDEX_MAGIC.length; i >= 0; i--) {
                for (int j = 0; j < INDEX_MAGIC.length; j++) {
                    if (tail[i + j] != INDEX_MAGIC[j]) continue outer;
                }
                indexPos = i;
                break;
            }
            if (indexPos < 0) throw new IOException("Block offset index not found in file tail");

            int pos = indexPos + INDEX_MAGIC.length;

            if (pos + 4 > tail.length) throw new EOFException("Index header truncated");

            int count = ((tail[pos] & 0xff) | ((tail[pos + 1] & 0xff) << 8) | ((tail[pos + 2] & 0xff) << 16) | ((tail[pos + 3] & 0xff) << 24));
            pos += 4;

            if (pos + count * 8 > tail.length) throw new EOFException("Index entries truncated");

            long[] offsets = new long[count];
            for (int i = 0; i < count; i++) {
                long off = 0L;
                for (int b = 0; b < 8; b++) {
                    off |= ((long) (tail[pos++] & 0xff)) << (8 * b);
                }
                offsets[i] = off;
            }
            return offsets;
        }
    }

    /**
     * 获取索引部分长度，用于确定尾部索引大小(20KB尾部内搜索)
     *
     * @param raf RandomAccessFile对象
     * @return 索引部分长度字节数，找不到返回0
     * @throws IOException IO异常
     */
    private static long getIndexSectionLength(RandomAccessFile raf) throws IOException {
        long fileLen = raf.length();
        long searchLen = Math.min(fileLen, 20 * 1024);
        byte[] tail = new byte[(int) searchLen];
        raf.seek(fileLen - searchLen);
        raf.readFully(tail);

        int ix = -1;
        outer:
        for (int i = tail.length - INDEX_MAGIC.length; i >= 0; i--) {
            for (int k = 0; k < INDEX_MAGIC.length; k++) {
                if (tail[i + k] != INDEX_MAGIC[k]) continue outer;
            }
            ix = i;
            break;
        }
        if (ix < 0)
            return 0;

        int pos = ix + INDEX_MAGIC.length;
        if (pos + 4 > tail.length) return 0;

        int count = ((tail[pos] & 0xff) | ((tail[pos + 1] & 0xff) << 8) | ((tail[pos + 2] & 0xff) << 16) | ((tail[pos + 3] & 0xff) << 24));

        long idxLen = INDEX_MAGIC.length + 4 + (long) count * 8 + 12; 
        // 10-byte index magic + 4-byte count + count*8 block offsets + 4 bytes crc + 8 bytes original size padding
        return idxLen;
    }

    /**
     * 读取解压后的原始文件大小。文件尾部存储原始长度。
     *
     * @param f 压缩文件
     * @return 原始文件大小（字节）
     * @throws IOException 读取异常
     */
    private static long readOriginalSize(File f) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long fileLength = raf.length();
            long indexPos = -1;

            long searchMax = Math.min(fileLength, 20 * 1024);
            byte[] tail = new byte[(int) searchMax];
            raf.seek(fileLength - searchMax);
            raf.readFully(tail);

            int ix = -1;
            outer:
            for (int i = tail.length - INDEX_MAGIC.length; i >= 0; i--) {
                for (int k = 0; k < INDEX_MAGIC.length; k++) {
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

            long sizePos = indexPos - 12; // CRC(4 bytes) + OriginalSize(8 bytes)
            if (sizePos < 0)
                throw new IOException("File structure error: Not enough space for original size metadata.");

            raf.seek(sizePos);
            int crcVal = readIntLE(raf);
            long originalSize = readLongLE(raf);
            if (originalSize < 0)
                throw new IOException("Invalid original size value.");
            return originalSize;
        }
    }

    /* ================== 信息列表 ================== */

    /**
     * 打印压缩文件信息
     */
    public static void listInfo(File inputFile) throws IOException {
        System.out.println("RAZFPlus Compressed File Info:");
        try (InputStream fis = new FileInputStream(inputFile)) {
            int blockSize = parseHeader(fis);
            System.out.println("  Block Size: " + blockSize);
        }
        try {
            long origSize = readOriginalSize(inputFile);
            System.out.println("  Original File Size: " + origSize + " bytes");
        } catch (Exception e) {
            System.out.println("  Original File Size: (unknown)");
        }
        System.out.println("  Compressed File Size: " + inputFile.length() + " bytes");

        try {
            long[] offsets = readIndex(inputFile);
            System.out.println("  Block Count: " + offsets.length);
            System.out.print("  Data Block Offsets: ");
            for (int i = 0; i < offsets.length; i++) {
                System.out.print(offsets[i]);
                if (i < offsets.length - 1) System.out.print(", ");
            }
            System.out.println();
        } catch (Exception e) {
            System.out.println("  Data Block Offsets: Index not found or parse error.");
        }
    }

    /* ================== 头部写/解析 ================== */

    /***
     * 写入GZIP头部信息及扩展字段中存储块大小
     *
     * @param out       输出流，必须支持write
     * @param blockSize 块大小，以字节为单位
     * @throws IOException IO异常
     */
    private static void writeHeader(OutputStream out, int blockSize) throws IOException {
        // GZIP 标准头
        out.write(GZIP_ID1);
        out.write(GZIP_ID2);
        out.write(GZIP_CM);
        out.write(GZIP_FLG);
        writeIntLE(out, 0); // mtime
        out.write(0);       // xflags
        out.write(GZIP_OS); // OS

        // Extra field
        writeShortLE(out, 8); // xlen
        // 子字段: 'RA', 'ZA', 类型和长度
        out.write('R');
        out.write('A');
        writeShortLE(out, 4);
        writeIntLE(out, blockSize);
    }

    /**
     * 解析GZIP/RAZFPlus头，返回块大小。该方法对输入流顺序消费bytes。
     *
     * @param in 输入流
     * @return 读取的块大小
     * @throws IOException
     */
    public static int parseHeader(InputStream in) throws IOException {
        byte[] buf = new byte[GZIP_HEADER_SIZE];
        int got = in.read(buf);
        if (got != GZIP_HEADER_SIZE)
            throw new IOException("File too short or incomplete GZIP header.");
        if (buf[0] != GZIP_ID1 || buf[1] != GZIP_ID2 || buf[2] != GZIP_CM)
            throw new IOException("Not a valid GZIP/RAZFPlus file.");

        if ((buf[3] & GZIP_FLG) != GZIP_FLG)
            throw new IOException("Missing GZIP FEXTRA flag, not RAZFPlus format.");

        int xlen = readShortLE(in);
        if (xlen < 8)
            throw new IOException("Invalid RAZFPlus extra field length.");

        byte[] extra = new byte[xlen];
        int r = in.read(extra);
        if (r != xlen)
            throw new IOException("Unexpected EOF reading GZIP extra.");

        // 解析扩展字段找到块大小
        for (int pos = 0; pos + 4 <= xlen; ) {
            byte s1 = extra[pos], s2 = extra[pos + 1];
            int slen = (extra[pos + 2] & 0xff) | ((extra[pos + 3] & 0xff) << 8);
            if (pos + 4 + slen > xlen) break;
            if (s1 == 'R' && s2 == 'A' && slen == 4) {
                int b0 = extra[pos + 4] & 0xff;
                int b1 = extra[pos + 5] & 0xff;
                int b2 = extra[pos + 6] & 0xff;
                int b3 = extra[pos + 7] & 0xff;
                return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            }
            pos += 4 + slen;
        }

        throw new IOException("RAZFPlus block size tag missing in extra field.");
    }

    /* ================== 辅助写读取小端 ================== */

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
        for (int i = 0; i < 8; i++)
            o.write((int) (v >>> (8 * i)) & 0xff);
    }

    private static int readShortLE(InputStream o) throws IOException {
        int b0 = o.read();
        int b1 = o.read();
        if ((b0 | b1) < 0) throw new EOFException();
        return ((b1 & 0xff) << 8) | (b0 & 0xff);
    }

    private static int readIntLE(RandomAccessFile raf) throws IOException {
        int b0 = raf.read();
        int b1 = raf.read();
        int b2 = raf.read();
        int b3 = raf.read();
        if ((b0 | b1 | b2 | b3) < 0) throw new EOFException();
        return (b0 & 0xff) | ((b1 & 0xff) << 8) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 24);
    }

    private static long readLongLE(RandomAccessFile raf) throws IOException {
        long r = 0;
        for (int i = 0; i < 8; i++) {
            int b = raf.read();
            if (b < 0) throw new EOFException();
            r |= ((long) b & 0xff) << (8 * i);
        }
        return r;
    }

    /* ========== 输出流计数，用于计算文件偏移 ========== */

    /**
     * 统计字节数的输出流，包装目标输出流。
     */
    public static class ByteCounterOutputStream extends FilterOutputStream {
        private long count = 0;

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

    /* ================== 辅助方法 ================== */

    /**
     * 根据操作类型生成默认输出文件名。
     *
     * @param inputFileName 输入文件名
     * @param op            操作 compress or decompress
     * @return 生成的输出路径，包含父路径
     */
    public static String getOutputFileName(String inputFileName, String op) {
        File inputFile = new File(inputFileName);
        String parent = inputFile.getParent();
        String name = inputFile.getName();
        String outputName;

        if ("compress".equalsIgnoreCase(op)) {
            outputName = name.toLowerCase().endsWith(".rz") ? name : name + ".rz";
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
}