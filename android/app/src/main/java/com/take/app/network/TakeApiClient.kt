package com.take.app.network

import com.take.app.crypto.TakeCrypto
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.math.BigInteger
import java.util.concurrent.TimeUnit

/**
 * TAKE API Client
 * All HTTP calls to the Flask server.
 * Runs on background thread — call from coroutine.
 */
class TakeApiClient(private val serverUrl: String) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val JSON = "application/json; charset=utf-8".toMediaType()

    // ─────────────────────────────────────────────────────────────
    // Helper
    // ─────────────────────────────────────────────────────────────

    private fun post(path: String, body: JSONObject): JSONObject {
        val request = Request.Builder()
            .url("$serverUrl$path")
            .post(body.toString().toRequestBody(JSON))
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string()
                ?: throw Exception("Empty response from server")

            val json = JSONObject(responseBody)

            if (!response.isSuccessful) {
                val error = json.optString("error", "Unknown server error")
                throw Exception("Server error ${response.code}: $error")
            }

            return json
        }
    }

    private fun get(path: String): JSONObject {
        val request = Request.Builder()
            .url("$serverUrl$path")
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            val responseBody = response.body?.string()
                ?: throw Exception("Empty response")
            return JSONObject(responseBody)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Health check
    // ─────────────────────────────────────────────────────────────

    fun healthCheck(): Boolean {
        return try {
            val resp = get("/health")
            resp.getString("status") == "ok"
        } catch (e: Exception) {
            false
        }
    }

    // ─────────────────────────────────────────────────────────────
    // REGISTRATION
    // ─────────────────────────────────────────────────────────────

    /**
     * Registration step 1:
     * Send blinded factor to server, get OPRF response back.
     * Paper: server computes blinded^(k1*k2^-1) inside TEE.
     */
    fun registerInit(
        idU: String,
        blindedFactor: BigInteger
    ): BigInteger {
        val body = JSONObject().apply {
            put("id_u", idU)
            put("blinded_factor", TakeCrypto.bigIntToB64(blindedFactor))
        }
        val resp = post("/register/init", body)
        return TakeCrypto.b64ToBigInt(resp.getString("oprf_response"))
    }

    /**
     * Registration step 2:
     * Send {IDU, P, C} to server for storage.
     */
    fun registerFinalize(
        idU: String,
        helperP: ByteArray,
        credentialC: BigInteger,
        passwordHash: String = ""
    ): Int {
        val body = JSONObject().apply {
            put("id_u", idU)
            put("helper_p", TakeCrypto.bytesToB64(helperP))
            put("credential_c", TakeCrypto.bigIntToB64(credentialC))
            if (passwordHash.isNotEmpty()) {
                put("password_hash", passwordHash)
            }
        }
        val resp = post("/register/finalize", body)
        return resp.getInt("user_id")
    }

    // ─────────────────────────────────────────────────────────────
    // AUTHENTICATION
    // ─────────────────────────────────────────────────────────────

    /**
     * Auth step 1:
     * Send IDU, get helper string P back.
     * Paper: server retrieves P from database.
     *
     * NOTE: In fingerprint-only mode, P is not used for Rep.
     * We still retrieve it for protocol completeness and future extension.
     */
    fun authInit(idU: String): ByteArray {
        val body = JSONObject().apply { put("id_u", idU) }
        val resp = post("/auth/init", body)
        return TakeCrypto.b64ToBytes(resp.getString("helper_p"))
    }

    /**
     * Auth step 2:
     * Send blinded factor + DH public key X.
     * Get OPRF response + server DH public key Y.
     */
    data class AuthOprfResult(
        val oprfResponse: BigInteger,
        val Y: BigInteger,
        val idS: String
    )

    fun authOprf(
        idU: String,
        blindedFactor: BigInteger,
        dhX: BigInteger
    ): AuthOprfResult {
        val body = JSONObject().apply {
            put("id_u", idU)
            put("blinded_factor", TakeCrypto.bigIntToB64(blindedFactor))
            put("dh_X", TakeCrypto.bigIntToB64(dhX))
        }
        val resp = post("/auth/oprf", body)
        return AuthOprfResult(
            oprfResponse = TakeCrypto.b64ToBigInt(resp.getString("oprf_response")),
            Y             = TakeCrypto.b64ToBigInt(resp.getString("dh_Y")),
            idS           = resp.getString("id_s")
        )
    }

    /**
     * Auth step 3:
     * Send σ1 to server for verification.
     * Get σ2 back for client to verify.
     */
    fun authVerify(idU: String, sigma1: ByteArray): ByteArray {
        val body = JSONObject().apply {
            put("id_u", idU)
            put("sigma1", TakeCrypto.bytesToB64(sigma1))
        }
        val resp = post("/auth/verify", body)
        return TakeCrypto.b64ToBytes(resp.getString("sigma2"))
    }
}
