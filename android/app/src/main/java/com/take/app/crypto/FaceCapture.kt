package com.take.app.crypto

import android.content.Context
import android.graphics.Bitmap
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

/**
 * TAKE Face Biometric Module (Android) — MobileFaceNet
 *
 * Uses a pre-trained MobileFaceNet TFLite model to extract a
 * face embedding from a cropped face image.
 * The embedding is then quantized to a 128-byte bitstring
 * for use with the fuzzy extractor.
 *
 * Dynamically adapts to the model's actual input/output tensor shapes
 * so it works with both single-face embedding models and dual-face
 * comparison models.
 */
object FaceCapture {

    // Fixed quantization range — matches Python biometric.py
    private const val EMBED_MIN = -0.6
    private const val EMBED_MAX = 0.6
    private const val EMBED_RANGE = EMBED_MAX - EMBED_MIN  // 1.2

    // MobileFaceNet standard input size
    private const val INPUT_SIZE = 112

    // Number of output bytes for the fuzzy extractor
    private const val OUTPUT_BYTES = 128

    private var interpreter: Interpreter? = null
    private var modelInputSize = 0    // total bytes the model expects
    private var modelOutputDim = 0    // number of floats in output

    /**
     * Initialize the TFLite interpreter. Call once at startup.
     */
    fun init(context: Context) {
        if (interpreter != null) return
        val model = loadModelFile(context, "mobilefacenet.tflite")
        val interp = Interpreter(model)

        // Query the model's actual input/output tensor shapes
        val inputTensor = interp.getInputTensor(0)
        modelInputSize = inputTensor.numBytes()
        val inputShape = inputTensor.shape()  // e.g., [1,112,112,3] or [2,112,112,3]

        val outputTensor = interp.getOutputTensor(0)
        val outputShape = outputTensor.shape()
        modelOutputDim = outputShape.last()

        android.util.Log.d("FaceCapture", "Model input shape: ${inputShape.toList()}, bytes=$modelInputSize")
        android.util.Log.d("FaceCapture", "Model output shape: ${outputShape.toList()}, dim=$modelOutputDim")

        interpreter = interp
    }

    /**
     * Process a cropped face bitmap into a 128-byte biometric bitstring.
     *
     * Steps:
     *   1. Resize to 112×112
     *   2. Normalize pixel values to [-1, 1]
     *   3. Run through MobileFaceNet → embedding
     *   4. L2-normalize the embedding
     *   5. Take first 128 dimensions, quantize to [0, 255] using fixed range
     *
     * @param faceBitmap  Cropped face image
     * @return 128-byte bitstring for the fuzzy extractor
     */
    fun bitmapToBitstring(faceBitmap: Bitmap): ByteArray {
        val interp = interpreter
            ?: throw IllegalStateException("FaceCapture not initialized. Call init() first.")

        // 1. Resize to 112×112
        val resized = Bitmap.createScaledBitmap(faceBitmap, INPUT_SIZE, INPUT_SIZE, true)

        // 2. Prepare a single face image as float buffer
        val singleFaceBytes = 4 * INPUT_SIZE * INPUT_SIZE * 3
        val pixels = IntArray(INPUT_SIZE * INPUT_SIZE)
        resized.getPixels(pixels, 0, INPUT_SIZE, 0, 0, INPUT_SIZE, INPUT_SIZE)

        // Allocate the full input buffer (might be 1x or 2x a single face)
        val inputBuffer = ByteBuffer.allocateDirect(modelInputSize)
        inputBuffer.order(ByteOrder.nativeOrder())

        // Write the face pixels (normalised to [-1,1])
        for (pixel in pixels) {
            val r = ((pixel shr 16) and 0xFF)
            val g = ((pixel shr 8) and 0xFF)
            val b = (pixel and 0xFF)
            inputBuffer.putFloat((r - 127.5f) / 128.0f)
            inputBuffer.putFloat((g - 127.5f) / 128.0f)
            inputBuffer.putFloat((b - 127.5f) / 128.0f)
        }

        // If the model expects more data (e.g. a second face slot), duplicate
        if (modelInputSize > singleFaceBytes) {
            for (pixel in pixels) {
                val r = ((pixel shr 16) and 0xFF)
                val g = ((pixel shr 8) and 0xFF)
                val b = (pixel and 0xFF)
                inputBuffer.putFloat((r - 127.5f) / 128.0f)
                inputBuffer.putFloat((g - 127.5f) / 128.0f)
                inputBuffer.putFloat((b - 127.5f) / 128.0f)
            }
        }

        // 3. Run inference
        // Determine output buffer shape from model
        val outputTensor = interp.getOutputTensor(0)
        val outputShape = outputTensor.shape()
        val totalOutputFloats = outputShape.fold(1) { acc, v -> acc * v }
        val flatOutput = FloatArray(totalOutputFloats)
        val outputBuffer = ByteBuffer.allocateDirect(totalOutputFloats * 4)
        outputBuffer.order(ByteOrder.nativeOrder())

        inputBuffer.rewind()
        interp.run(inputBuffer, outputBuffer)

        // Read floats from output buffer
        outputBuffer.rewind()
        for (i in flatOutput.indices) {
            flatOutput[i] = outputBuffer.float
        }

        // Use the output as our embedding
        val embedding = flatOutput

        // 4. L2-normalize the embedding
        var norm = 0.0
        for (v in embedding) norm += v * v
        norm = sqrt(norm)
        if (norm > 0) {
            for (i in embedding.indices) embedding[i] = (embedding[i] / norm.toFloat())
        }

        // 5. Quantize first OUTPUT_BYTES dimensions to bytes
        val result = ByteArray(OUTPUT_BYTES)
        for (i in 0 until OUTPUT_BYTES) {
            val value = if (i < embedding.size) embedding[i].toDouble() else 0.0
            val clipped = max(EMBED_MIN, min(EMBED_MAX, value))
            val normalized = (clipped - EMBED_MIN) / EMBED_RANGE
            result[i] = (normalized * 255).toInt().coerceIn(0, 255).toByte()
        }

        return result
    }

    /**
     * Release TFLite resources.
     */
    fun close() {
        interpreter?.close()
        interpreter = null
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private fun loadModelFile(context: Context, filename: String): MappedByteBuffer {
        val assetFileDescriptor = context.assets.openFd(filename)
        val inputStream = FileInputStream(assetFileDescriptor.fileDescriptor)
        val fileChannel = inputStream.channel
        val startOffset = assetFileDescriptor.startOffset
        val declaredLength = assetFileDescriptor.declaredLength
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
    }
}
