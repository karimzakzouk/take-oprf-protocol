package com.take.app.crypto

import org.bouncycastle.crypto.digests.SHA3Digest
import java.security.SecureRandom

/**
 * TAKE Fuzzy Extractor — BCH implementation
 * Kotlin port of server/crypto/fuzzy_extractor.py
 *
 * Must produce byte-identical output to the Python version.
 *
 * Gen(bio) → (R, P)
 *   bio: 128-byte biometric bitstring
 *   R:   32-byte secret string (used in combined factor H0(pw||R))
 *   P:   128-byte public helper string
 *        = 32-byte nonce (LSB of byte[31] holds extra_bit)
 *        + 96-byte BCH syndrome
 *
 * Rep(bio', P) → R
 *   Recovers same R if Hamming(bio, bio') <= TOLERANCE (=24)
 *
 * BCH parameters:
 *   GF(2^10), primitive polynomial x^10 + x^3 + 1 = 0x409
 *   Code length n = 1023 bits
 *   Error correction t = 24 bit-flips
 *   Syndrome = 2*24*2 = 96 bytes
 *
 * This replaces the previous XOR-sketch implementation which had
 * zero real error correction (it just unmasked bio directly).
 */
object FuzzyExtractor {

    // ─────────────────────────────────────────────────────────────
    // BCH parameters — must match Python exactly
    // ─────────────────────────────────────────────────────────────

    private const val GF_M    = 10
    private const val GF_SIZE = 1 shl GF_M        // 1024
    private const val GF_POLY = 0x409              // x^10 + x^3 + 1
    private const val BCH_N   = GF_SIZE - 1        // 1023
    const val BCH_T           = 24                 // error correction capability
    const val TOLERANCE       = BCH_T              // max correctable bit-flips

    private const val BIO_BYTES       = 128
    private const val P_NONCE_BYTES   = 32
    private const val SYN_ELEM_BYTES  = 2           // each GF(2^10) element → 2 bytes
    private const val SYN_BYTES       = 2 * BCH_T * SYN_ELEM_BYTES  // 96 bytes
    private const val P_TOTAL         = P_NONCE_BYTES + SYN_BYTES    // 128 bytes

    private val rng = SecureRandom()

    // ─────────────────────────────────────────────────────────────
    // GF(2^10) lookup tables — built once at class load
    // ─────────────────────────────────────────────────────────────

    private val gfExp = IntArray(2 * GF_SIZE)
    private val gfLog = IntArray(GF_SIZE)

    init {
        var x = 1
        for (i in 0 until BCH_N) {
            gfExp[i] = x
            gfLog[x] = i
            x = x shl 1
            if (x and GF_SIZE != 0) x = x xor GF_POLY
        }
        for (i in BCH_N until 2 * GF_SIZE) {
            gfExp[i] = gfExp[i - BCH_N]
        }
    }

    // ─────────────────────────────────────────────────────────────
    // GF arithmetic
    // ─────────────────────────────────────────────────────────────

    private fun gfMul(a: Int, b: Int): Int {
        if (a == 0 || b == 0) return 0
        return gfExp[(gfLog[a] + gfLog[b]) % BCH_N]
    }

    private fun gfInv(a: Int): Int {
        require(a != 0) { "GF inverse of zero" }
        return gfExp[BCH_N - gfLog[a]]
    }

    // ─────────────────────────────────────────────────────────────
    // BCH syndrome computation
    //
    // S_i = sum_{j=0}^{n-1} bits[j] * alpha^(i*j)   for i in 1..2t
    //
    // Linearity: syn(a XOR b) = syn(a) XOR syn(b)
    // So: syn(bio') XOR syn(bio) = syn(error_pattern)
    // ─────────────────────────────────────────────────────────────

    private fun computeSyndromes(bits: IntArray, t: Int = BCH_T): IntArray {
        val syn = IntArray(2 * t)
        for (i in 1..2 * t) {
            var s = 0
            for (j in bits.indices) {
                if (bits[j] != 0) {
                    s = s xor gfExp[(i * j) % BCH_N]
                }
            }
            syn[i - 1] = s
        }
        return syn
    }

    // ─────────────────────────────────────────────────────────────
    // Berlekamp-Massey algorithm
    // Finds the error locator polynomial sigma from the syndromes.
    // ─────────────────────────────────────────────────────────────

    private fun berlekampMassey(syndromes: IntArray): IntArray {
        val n = syndromes.size
        var C = intArrayOf(1)
        var B = intArrayOf(1)
        var L = 0
        var m = 1
        var b = 1

        for (i in 0 until n) {
            var d = syndromes[i]
            for (j in 1..L) {
                if (j < C.size) {
                    d = d xor gfMul(C[j], syndromes[i - j])
                }
            }

            if (d == 0) {
                m++
            } else if (2 * L <= i) {
                val T = C.copyOf()
                val coeff = gfMul(d, gfInv(b))
                if (C.size < B.size + m) C = C.copyOf(B.size + m)
                for (j in B.indices) {
                    C[j + m] = C[j + m] xor gfMul(coeff, B[j])
                }
                L = i + 1 - L
                B = T
                b = d
                m = 1
            } else {
                val coeff = gfMul(d, gfInv(b))
                if (C.size < B.size + m) C = C.copyOf(B.size + m)
                for (j in B.indices) {
                    C[j + m] = C[j + m] xor gfMul(coeff, B[j])
                }
                m++
            }
        }
        return C
    }

    // ─────────────────────────────────────────────────────────────
    // Chien search
    // Finds all roots of sigma(x) in GF(2^10).
    // alpha^(-j) is a root → bit position j is an error.
    // ─────────────────────────────────────────────────────────────

    private fun chienSearch(sigma: IntArray): IntArray {
        val errors = mutableListOf<Int>()
        for (i in 0 until BCH_N) {
            var v = 0
            for (j in sigma.indices) {
                v = v xor gfMul(sigma[j], gfExp[(j * (BCH_N - i)) % BCH_N])
            }
            if (v == 0) errors.add(i)
        }
        return errors.toIntArray()
    }

    // ─────────────────────────────────────────────────────────────
    // BCH decode: error syndrome → error positions
    // ─────────────────────────────────────────────────────────────

    private fun bchDecodeErrorSyndrome(synError: IntArray): IntArray {
        if (synError.all { it == 0 }) return intArrayOf()

        val sigma     = berlekampMassey(synError)
        val numErrors = sigma.size - 1

        if (numErrors > BCH_T) {
            throw IllegalArgumentException(
                "Uncorrectable: $numErrors errors exceed BCH_T=$BCH_T"
            )
        }

        val errors = chienSearch(sigma)

        if (errors.size != numErrors) {
            throw IllegalArgumentException(
                "Chien search found ${errors.size} roots, expected $numErrors — " +
                "biometric too different or helper string corrupted"
            )
        }

        return errors
    }

    // ─────────────────────────────────────────────────────────────
    // Syndrome serialization — matches Python _syn_to_bytes / _bytes_to_syn
    // Each GF(2^10) element stored as 2 bytes big-endian
    // ─────────────────────────────────────────────────────────────

    private fun synToBytes(syn: IntArray): ByteArray {
        val result = ByteArray(syn.size * SYN_ELEM_BYTES)
        for (i in syn.indices) {
            result[i * 2]     = ((syn[i] shr 8) and 0xFF).toByte()
            result[i * 2 + 1] = (syn[i] and 0xFF).toByte()
        }
        return result
    }

    private fun bytesToSyn(b: ByteArray): IntArray {
        val count = b.size / SYN_ELEM_BYTES
        return IntArray(count) { i ->
            ((b[i * 2].toInt() and 0xFF) shl 8) or (b[i * 2 + 1].toInt() and 0xFF)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Bio ↔ bit array conversion
    // ─────────────────────────────────────────────────────────────

    private fun bioToBits(bio: ByteArray): IntArray {
        val bits = IntArray(bio.size * 8)
        var idx = 0
        for (byte in bio) {
            for (i in 7 downTo 0) {
                bits[idx++] = (byte.toInt() shr i) and 1
            }
        }
        return bits
    }

    private fun bitsToBio(bits: IntArray): ByteArray {
        require(bits.size == BIO_BYTES * 8)
        val result = ByteArray(BIO_BYTES)
        for (i in 0 until BIO_BYTES) {
            var byte = 0
            for (j in 0 until 8) {
                byte = (byte shl 1) or bits[i * 8 + j]
            }
            result[i] = byte.toByte()
        }
        return result
    }

    // ─────────────────────────────────────────────────────────────
    // SHA3-256
    // ─────────────────────────────────────────────────────────────

    private fun sha3_256(data: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    // ─────────────────────────────────────────────────────────────
    // PUBLIC API: Gen and Rep
    // ─────────────────────────────────────────────────────────────

    data class GenResult(val R: ByteArray, val P: ByteArray)

    /**
     * Generation algorithm — Dodis et al. code-offset secure sketch.
     *
     * @param bio  128-byte biometric bitstring
     * @return GenResult with R (32 bytes) and P (128 bytes = 32 nonce + 96 syndrome)
     */
    fun Gen(bio: ByteArray): GenResult {
        require(bio.size == BIO_BYTES) {
            "Expected $BIO_BYTES-byte biometric, got ${bio.size}"
        }

        val bits      = bioToBits(bio)        // 1024 bits
        val bchBits   = bits.sliceArray(0 until BCH_N)  // first 1023 bits
        val extraBit  = bits[BCH_N]           // bit 1023

        // Random nonce, extra_bit packed into LSB of last byte
        val rawNonce = ByteArray(P_NONCE_BYTES)
        rng.nextBytes(rawNonce)
        rawNonce[31] = ((rawNonce[31].toInt() and 0xFE) or extraBit).toByte()
        val nonce = rawNonce

        // Compute BCH syndromes
        val syn   = computeSyndromes(bchBits)
        val synB  = synToBytes(syn)

        // R = SHA3-256(nonce || bio) — never stored
        val R = sha3_256(nonce + bio)

        // P = nonce || syndrome
        val P = nonce + synB

        return GenResult(R, P)
    }

    /**
     * Reproduction algorithm — Dodis et al. code-offset construction.
     *
     * @param bioPrime  128-byte new biometric scan
     * @param P         128-byte helper string from Gen
     * @return R — same secret as Gen iff Hamming(bio, bio') <= TOLERANCE
     * @throws IllegalArgumentException if biometric too different
     */
    fun Rep(bioPrime: ByteArray, P: ByteArray): ByteArray {
        require(bioPrime.size == BIO_BYTES) {
            "Expected $BIO_BYTES-byte biometric, got ${bioPrime.size}"
        }
        require(P.size == P_TOTAL) {
            "Malformed helper string P: expected $P_TOTAL bytes, got ${P.size}"
        }

        val nonce     = P.sliceArray(0 until P_NONCE_BYTES)
        val synB      = P.sliceArray(P_NONCE_BYTES until P_TOTAL)
        val extraBit  = nonce[31].toInt() and 1
        val synStored = bytesToSyn(synB)          // syn(bio)

        // Compute syndrome of noisy bio'
        val bitsPrime = bioToBits(bioPrime)
        val bchBitsP  = bitsPrime.sliceArray(0 until BCH_N)
        val synPrime  = computeSyndromes(bchBitsP)

        // Error syndrome: syn(bio') XOR syn(bio) = syn(error_pattern)
        val synError  = IntArray(synStored.size) { i -> synPrime[i] xor synStored[i] }

        // BCH decode — find and correct bit-flips
        val errorPositions = try {
            bchDecodeErrorSyndrome(synError)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException(
                "Biometric too different — authentication failed. ${e.message}"
            )
        }

        val correctedBits = bchBitsP.copyOf()
        for (pos in errorPositions) {
            correctedBits[pos] = correctedBits[pos] xor 1
        }

        // Reconstruct full 1024-bit bio: corrected 1023 bits + extra_bit from nonce
        val fullBits = IntArray(BIO_BYTES * 8)
        correctedBits.copyInto(fullBits, 0, 0, BCH_N)
        fullBits[BCH_N] = extraBit

        val recoveredBio = bitsToBio(fullBits)

        // Re-derive R
        return sha3_256(nonce + recoveredBio)
    }

    // ─────────────────────────────────────────────────────────────
    // Utility: add noise (for testing only)
    // ─────────────────────────────────────────────────────────────

    fun addNoise(bio: ByteArray, nFlips: Int = 10): ByteArray {
        val bits      = bioToBits(bio).toMutableList()
        val positions = (bits.indices).shuffled().take(nFlips)
        for (pos in positions) bits[pos] = bits[pos] xor 1
        return bitsToBio(bits.toIntArray())
    }
}