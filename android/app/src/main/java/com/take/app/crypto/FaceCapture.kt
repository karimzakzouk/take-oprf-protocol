package com.take.app.crypto

import android.content.Context
import android.graphics.Bitmap
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlin.math.sqrt

/**
 * TAKE Face Biometric Module (Android) — MobileFaceNet
 *
 * Uses a pre-trained MobileFaceNet TFLite model to extract a
 * face embedding from a cropped face image, then converts it
 * to a 128-byte biometric bitstring for the fuzzy extractor.
 *
 * Quantization:
 *   Sign-bit encoding — 1 bit per embedding dimension.
 *   bit[i] = 1 if embedding[i] >= 0, else 0.
 *   128 bits packed MSB-first into 16 bytes, zero-padded to 128 bytes.
 *
 *   WHY sign bits instead of 8-bit fixed-range:
 *     The previous 8-bit quantization (0..255 per dimension) produced
 *     ~170 bit flips between two scans of the same face, because a
 *     small float shift of ~0.007 moves ~1.5 quantization steps,
 *     each flipping 1-3 bits across 128 dimensions.
 *     This far exceeded BCH_T=24, breaking the fuzzy extractor.
 *
 *     Sign bits flip only when noise pushes a value across zero.
 *     For dlib/MobileFaceNet L2-normalized embeddings (~N(0,0.09))
 *     with realistic inter-scan noise (~0.005-0.01 std), this gives
 *     0-3 sign flips total — well within BCH_T=24.
 *
 * This matches server/crypto/biometric.py embedding_to_bitstring() exactly.
 */
object FaceCapture {

    // MobileFaceNet standard input size
    private const val INPUT_SIZE = 112

    // Number of output bytes for the fuzzy extractor
    private const val OUTPUT_BYTES = 128

    // Sign bits: 1 per embedding dimension
    private const val SIGN_BITS  = 128          // one per embedding dimension
    private const val SIGN_BYTES = SIGN_BITS / 8  // 16 packed bytes
    private const val PADDING_BYTES = OUTPUT_BYTES - SIGN_BYTES  // 112 zero bytes

    private var interpreter: Interpreter? = null
    private var modelInputSize = 0
    private var modelOutputDim = 0

    /**
     * Initialize the TFLite interpreter. Call once at startup.
     */
    fun init(context: Context) {
        if (interpreter != null) return
        val model  = loadModelFile(context, "mobilefacenet.tflite")
        val interp = Interpreter(model)

        val inputTensor  = interp.getInputTensor(0)
        modelInputSize   = inputTensor.numBytes()
        val outputTensor = interp.getOutputTensor(0)
        modelOutputDim   = outputTensor.shape().last()

        android.util.Log.d("FaceCapture",
            "Model input: ${inputTensor.shape().toList()}, bytes=$modelInputSize")
        android.util.Log.d("FaceCapture",
            "Model output: ${outputTensor.shape().toList()}, dim=$modelOutputDim")

        interpreter = interp
    }

    /**
     * Process a cropped face bitmap into a 128-byte biometric bitstring.
     *
     * Steps:
     *   1. Resize to 112×112
     *   2. Normalize pixels to [-1, 1]
     *   3. Run MobileFaceNet → raw embedding
     *   4. L2-normalize the embedding
     *   5. Sign-bit encode: bit[i] = 1 if embedding[i] >= 0
     *   6. Pack 128 bits into 16 bytes, zero-pad to 128 bytes
     *
     * @param faceBitmap  Cropped face image
     * @return 128-byte bitstring for the fuzzy extractor
     */
    fun bitmapToBitstring(faceBitmap: Bitmap): ByteArray {
        val interp = interpreter
            ?: throw IllegalStateException("FaceCapture not initialized. Call init() first.")

        // Step 1: Resize to 112×112
        val resized = Bitmap.createScaledBitmap(faceBitmap, INPUT_SIZE, INPUT_SIZE, true)

        // Step 2: Build input buffer (normalized to [-1, 1])
        val singleFaceBytes = 4 * INPUT_SIZE * INPUT_SIZE * 3
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        resized.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)

        val inputBuffer = ByteBuffer.allocateDirect(modelInputSize)
        inputBuffer.order(ByteOrder.nativeOrder())

        fun writePixels() {
            for (pixel in pixels) {
                inputBuffer.putFloat((((pixel shr 16) and 0xFF).toFloat() - 127.5f) / 128.0f)
                inputBuffer.putFloat((((pixel shr 8)  and 0xFF).toFloat() - 127.5f) / 128.0f)
                inputBuffer.putFloat(((pixel          and 0xFF).toFloat() - 127.5f) / 128.0f)
            }
        }
        writePixels()
        if (modelInputSize > singleFaceBytes) writePixels()  // dual-face model slot

        // Step 3: Run inference
        val outputTensor   = interp.getOutputTensor(0)
        val totalOutFloats = outputTensor.shape().fold(1) { acc, v -> acc * v }
        val outputBuffer   = ByteBuffer.allocateDirect(totalOutFloats * 4)
        outputBuffer.order(ByteOrder.nativeOrder())

        inputBuffer.rewind()
        interp.run(inputBuffer, outputBuffer)

        outputBuffer.rewind()
        val embedding = FloatArray(totalOutFloats) { outputBuffer.float }

        // Step 4: L2-normalize
        var norm = 0.0
        for (v in embedding) norm += v * v
        norm = sqrt(norm)
        if (norm > 0) {
            for (i in embedding.indices) embedding[i] /= norm.toFloat()
        }

        // Step 5 & 6: Sign-bit encode → pack into bytes → zero-pad
        return embeddingToSignBits(embedding)
    }

    /**
     * Convert a float embedding to 128-byte sign-bit bitstring.
     * Matches Python's embedding_to_bitstring() exactly.
     *
     * bit[i] = 1 if embedding[i] >= 0, else 0
     * 128 bits packed MSB-first into 16 bytes + 112 zero bytes = 128 bytes
     */
    fun embeddingToSignBits(embedding: FloatArray): ByteArray {
        // Pack 128 sign bits into 16 bytes (MSB first, matching numpy packbits)
        val packed = ByteArray(SIGN_BYTES)
        for (byteIdx in 0 until SIGN_BYTES) {
            var b = 0
            for (bitIdx in 0 until 8) {
                val dimIdx = byteIdx * 8 + bitIdx
                val signBit = if (dimIdx < embedding.size && embedding[dimIdx] >= 0f) 1 else 0
                b = (b shl 1) or signBit
            }
            packed[byteIdx] = b.toByte()
        }
        // Zero-pad to 128 bytes
        return packed + ByteArray(PADDING_BYTES)
    }

    /**
     * Release TFLite resources.
     */
    fun close() {
        interpreter?.close()
        interpreter = null
    }

    private fun loadModelFile(context: Context, filename: String): MappedByteBuffer {
        val afd         = context.assets.openFd(filename)
        val inputStream = FileInputStream(afd.fileDescriptor)
        val fileChannel = inputStream.channel
        return fileChannel.map(FileChannel.MapMode.READ_ONLY,
            afd.startOffset, afd.declaredLength)
    }
}