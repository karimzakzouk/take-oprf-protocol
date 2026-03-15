package com.take.app.crypto

import org.bouncycastle.crypto.digests.SHA3Digest
import java.security.SecureRandom

/**
 * TAKE Fuzzy Extractor — Kotlin port of server/crypto/fuzzy_extractor.py
 *
 * Must produce byte-identical output to the Python version.
 *
 * Gen(bio) → (R, P)
 *   bio: 128-byte biometric bitstring
 *   R:   32-byte secret string (used in combined factor H0(pw||R))
 *   P:   160-byte public helper string (32-byte nonce + 128-byte sketch)
 *
 * Rep(bio', P) → R
 *   Recovers same R if Hamming(bio, bio') <= TOLERANCE
 */
object FuzzyExtractor {

    // Max bit-flips between two scans of the same face
    // Real-world continuous embeddings quantized to bytes have high bit-level
    // variance (e.g. 127 to 128 flips 8 bits). Distance of 250-300 is expected for the same face.
    const val TOLERANCE = 350  // out of 1024 bits (~34% — standard for quantized FaceNet)

    private val rng = SecureRandom()

    // ─────────────────────────────────────────────────────────────
    // SHA3-256 helper (same as TakeCrypto, but self-contained)
    // ─────────────────────────────────────────────────────────────

    private fun sha3_256(data: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────

    private fun xorBytes(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "Length mismatch: ${a.size} vs ${b.size}" }
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }

    private fun hammingDistance(a: ByteArray, b: ByteArray): Int {
        require(a.size == b.size) { "Length mismatch: ${a.size} vs ${b.size}" }
        var distance = 0
        for (i in a.indices) {
            distance += Integer.bitCount((a[i].toInt() xor b[i].toInt()) and 0xFF)
        }
        return distance
    }

    /**
     * Generate pad from nonce — must match Python exactly:
     *   pad = SHA3_256(b"sketch_pad" + nonce)
     *   while len(pad) < target: pad += SHA3_256(pad)
     *   pad = pad[:target]
     */
    private fun generatePad(nonce: ByteArray, length: Int): ByteArray {
        var pad = sha3_256("sketch_pad".toByteArray() + nonce)
        while (pad.size < length) {
            pad = pad + sha3_256(pad)
        }
        return pad.copyOfRange(0, length)
    }

    /**
     * Derive secret R from bio + nonce — must match Python:
     *   SHA3_256(nonce + bio)
     */
    private fun deriveSecret(bio: ByteArray, nonce: ByteArray): ByteArray {
        return sha3_256(nonce + bio)
    }

    // ─────────────────────────────────────────────────────────────
    // Gen — Generation algorithm (Paper Section III-A)
    // ─────────────────────────────────────────────────────────────

    data class GenResult(val R: ByteArray, val P: ByteArray)

    /**
     * Generate (R, P) from biometric bitstring.
     *
     * @param bio  128-byte biometric bitstring
     * @return GenResult with R (32 bytes) and P (160 bytes = 32 nonce + 128 sketch)
     */
    fun Gen(bio: ByteArray): GenResult {
        require(bio.size == 128) { "Expected 128-byte biometric, got ${bio.size}" }

        // Random nonce
        val nonce = ByteArray(32)
        rng.nextBytes(nonce)

        // Compute sketch = bio XOR pad(nonce)
        val pad = generatePad(nonce, 128)
        val sketch = xorBytes(bio, pad)

        // Derive secret R
        val R = deriveSecret(bio, nonce)

        // Public helper P = nonce || sketch
        val P = nonce + sketch

        return GenResult(R, P)
    }

    // ─────────────────────────────────────────────────────────────
    // Rep — Reproduction algorithm (Paper Section III-A)
    // ─────────────────────────────────────────────────────────────

    /**
     * Recover R from noisy biometric + helper string P.
     *
     * @param bioPrime  128-byte new biometric scan
     * @param P         160-byte helper string from Gen
     * @return R (32-byte secret) — same as from Gen if bio' close enough
     * @throws IllegalArgumentException if biometric too different
     */
    fun Rep(bioPrime: ByteArray, P: ByteArray): ByteArray {
        require(bioPrime.size == 128) { "Expected 128-byte biometric, got ${bioPrime.size}" }

        // Unpack P
        val nonce = P.copyOfRange(0, 32)
        val sketch = P.copyOfRange(32, 160)
        require(sketch.size == 128) { "Malformed helper string P" }

        // Recover original bio: sketch = bio XOR pad → bio = sketch XOR pad
        val pad = generatePad(nonce, 128)
        val recoveredBio = xorBytes(sketch, pad)

        // Check Hamming distance
        val dist = hammingDistance(bioPrime, recoveredBio)
        if (dist > TOLERANCE) {
            throw IllegalArgumentException(
                "Biometric too different — authentication failed. " +
                "Hamming distance $dist exceeds tolerance of $TOLERANCE bits."
            )
        }

        // Re-derive R from recovered bio
        return deriveSecret(recoveredBio, nonce)
    }
}
