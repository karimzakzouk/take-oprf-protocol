package com.take.app.crypto

import android.util.Base64
import org.bouncycastle.crypto.digests.SHA3Digest
import java.math.BigInteger
import java.security.SecureRandom

/**
 * TAKE Cryptographic Primitives
 * Mirrors server/crypto/primitives.py exactly — same group, same hashes,
 * same OPRF, same DH. Both sides must produce identical results.
 */
object TakeCrypto {

    // ─────────────────────────────────────────────────────────────
    // GROUP PARAMETERS — 2048-bit RFC 3526 Group 14
    // ─────────────────────────────────────────────────────────────

    val Q: BigInteger = BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
    )

    val G: BigInteger = BigInteger.TWO
    val GROUP_ORDER: BigInteger = (Q - BigInteger.ONE) / BigInteger.TWO

    private val rng = SecureRandom()

    // ─────────────────────────────────────────────────────────────
    // SHA-3 helpers (Bouncy Castle)
    // ─────────────────────────────────────────────────────────────

    fun sha3_256(data: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(data, 0, data.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    fun sha3_224(data: ByteArray): ByteArray {
        val d = SHA3Digest(224)
        d.update(data, 0, data.size)
        val out = ByteArray(28)
        d.doFinal(out, 0)
        return out
    }

    // ─────────────────────────────────────────────────────────────
    // H0–H5 — must match Python exactly
    // ─────────────────────────────────────────────────────────────

    fun H0(data: ByteArray): BigInteger {
        val h = sha3_256(data)
        var s = BigInteger(1, h).mod(GROUP_ORDER)
        if (s == BigInteger.ZERO) s = BigInteger.ONE
        return G.modPow(s, Q)
    }

    fun H3(data: ByteArray): ByteArray = sha3_224(data)

    fun H4(data: ByteArray): ByteArray =
        sha3_224("H4_domain".toByteArray() + data)

    fun H5(data: ByteArray): ByteArray =
        sha3_256("H5_domain".toByteArray() + data)

    // ─────────────────────────────────────────────────────────────
    // CONCAT — each BigInteger = 256 bytes big-endian (matches Python)
    // ─────────────────────────────────────────────────────────────

    fun concat(vararg parts: Any): ByteArray {
        var result = ByteArray(0)
        for (part in parts) {
            result += when (part) {
                is BigInteger -> bigIntTo256Bytes(part)
                is ByteArray  -> part
                is String     -> part.toByteArray()
                else -> throw IllegalArgumentException("Unsupported: ${part::class}")
            }
        }
        return result
    }

    fun bigIntTo256Bytes(n: BigInteger): ByteArray {
        val raw = n.toByteArray()
        return when {
            raw.size < 256 -> ByteArray(256 - raw.size) + raw
            raw.size > 256 -> raw.takeLast(256).toByteArray()
            else           -> raw
        }
    }

    fun iduBytes(username: String): ByteArray =
        sha3_256(username.toByteArray()).take(4).toByteArray()

    // ─────────────────────────────────────────────────────────────
    // COMBINED FACTOR: H0(pw || R)
    // ─────────────────────────────────────────────────────────────

    fun combinedFactor(password: String, R: ByteArray): BigInteger =
        H0(password.toByteArray() + R)

    // ─────────────────────────────────────────────────────────────
    // OPRF client side
    // ─────────────────────────────────────────────────────────────

    data class BlindResult(val blinded: BigInteger, val r: BigInteger)

    fun oprfBlind(cf: BigInteger): BlindResult {
        var r = BigInteger(GROUP_ORDER.bitLength(), rng).mod(GROUP_ORDER)
        if (r == BigInteger.ZERO) r = BigInteger.ONE
        return BlindResult(cf.modPow(r, Q), r)
    }

    fun oprfUnblind(evaluated: BigInteger, r: BigInteger): BigInteger =
        evaluated.modPow(r.modInverse(GROUP_ORDER), Q)

    // ─────────────────────────────────────────────────────────────
    // DIFFIE-HELLMAN
    // ─────────────────────────────────────────────────────────────

    data class DHKeyPair(val priv: BigInteger, val pub: BigInteger)

    fun dhKeygen(): DHKeyPair {
        var x = BigInteger(GROUP_ORDER.bitLength(), rng).mod(GROUP_ORDER)
        if (x == BigInteger.ZERO) x = BigInteger.ONE
        return DHKeyPair(x, G.modPow(x, Q))
    }

    fun dhShared(priv: BigInteger, pubOther: BigInteger): BigInteger =
        pubOther.modPow(priv, Q)

    // ─────────────────────────────────────────────────────────────
    // BASE64 <-> BigInteger (256-byte encoding, matches Python)
    // ─────────────────────────────────────────────────────────────

    fun bigIntToB64(n: BigInteger): String =
        Base64.encodeToString(bigIntTo256Bytes(n), Base64.NO_WRAP)

    fun b64ToBigInt(s: String): BigInteger =
        BigInteger(1, Base64.decode(s, Base64.NO_WRAP))

    fun bytesToB64(b: ByteArray): String =
        Base64.encodeToString(b, Base64.NO_WRAP)

    fun b64ToBytes(s: String): ByteArray =
        Base64.decode(s, Base64.NO_WRAP)
}
