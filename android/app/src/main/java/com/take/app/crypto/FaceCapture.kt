package com.take.app.crypto

import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.facemesh.FaceMeshDetection
import com.google.mlkit.vision.facemesh.FaceMeshDetectorOptions
import com.google.mlkit.vision.facemesh.FaceMeshPoint
import kotlin.math.sqrt

/**
 * TAKE Face Biometric Module (Android)
 *
 * Uses ML Kit Face Mesh Detection to extract facial landmarks,
 * then computes a 128-dimensional embedding vector and quantizes
 * it to a 128-byte bitstring for use with the fuzzy extractor.
 *
 * This mirrors server/crypto/biometric.py but uses ML Kit instead of dlib.
 * The quantization range and method are identical.
 */
object FaceCapture {

    // Fixed quantization range — must match Python biometric.py
    private const val EMBED_MIN = -0.6
    private const val EMBED_MAX = 0.6
    private const val EMBED_RANGE = EMBED_MAX - EMBED_MIN  // 1.2

    /**
     * Create ML Kit face mesh detector configured for single face.
     */
    fun createDetector() = FaceMeshDetection.getClient(
        FaceMeshDetectorOptions.Builder()
            .setUseCase(FaceMeshDetectorOptions.FACE_MESH)
            .build()
    )

    /**
     * Convert ML Kit face mesh into a 128-byte (1024-bit) highly-discriminative bitstring.
     *
     * Instead of using absolute normalized distances (which are too similar between humans),
     * we use comparative distance features (similar to LBP or FaceNet triplets).
     * For 1024 bits, we select 1024 predefined pairs of pairs:
     *   Bit[i] = 1 if dist(A_i, B_i) > dist(C_i, D_i), else 0.
     * This is scale-invariant by definition and highly specific to individual facial structure.
     */
    fun meshToBitstring(meshPoints: List<FaceMeshPoint>): ByteArray {
        if (meshPoints.size < 468) {
            throw RuntimeException("Incomplete face mesh: ${meshPoints.size} points (need 468)")
        }

        // Get 3D coords
        val pts = meshPoints.sortedBy { it.index }.map {
            Triple(it.position.x.toDouble(), it.position.y.toDouble(), it.position.z.toDouble())
        }

        // Ensure we have a pseudo-random but deterministic way to select
        // 1024 pairs of pairs of landmarks (A,B vs C,D).
        // Using a fixed seed ensures the same pairs are always compared.
        val prng = java.util.Random(42)

        val result = ByteArray(128)
        for (byteIdx in 0 until 128) {
            var currentByte = 0
            for (bitIdx in 0 until 8) {
                // Select 4 random landmark indices (0 to 467)
                val a = prng.nextInt(468)
                val b = prng.nextInt(468)
                val c = prng.nextInt(468)
                val d = prng.nextInt(468)

                val distAB = dist3d(pts[a], pts[b])
                val distCD = dist3d(pts[c], pts[d])

                if (distAB > distCD) {
                    currentByte = currentByte or (1 shl bitIdx)
                }
            }
            result[byteIdx] = currentByte.toByte()
        }

        return result
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private fun dist3d(
        a: Triple<Double, Double, Double>,
        b: Triple<Double, Double, Double>
    ): Double {
        val dx = a.first - b.first
        val dy = a.second - b.second
        val dz = a.third - b.third
        return sqrt(dx * dx + dy * dy + dz * dz)
    }
}
