package com.take.app.ui

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.take.app.crypto.FuzzyExtractor
import com.take.app.crypto.KeystoreManager
import com.take.app.crypto.TakeCrypto
import com.take.app.databinding.ActivityLoginBinding
import com.take.app.network.TakeApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigInteger
import com.take.app.R

/**
 * Login screen — supports two biometric modes:
 *
 * FINGERPRINT mode:
 *   Fingerprint unlocks R from Keystore → OPRF auth.
 *
 * FACE mode (paper-faithful):
 *   authInit → get P from server → camera captures face → Rep(bio', P) → R → OPRF auth.
 *   This matches Section IV of the TAKE paper exactly.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var apiClient: TakeApiClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        keystoreManager = KeystoreManager(this)
        apiClient = TakeApiClient(RegisterActivity.SERVER_URL)
        
        binding.btnLogin.setOnClickListener { startLogin() }
    }

    private fun startLogin() {
        val idU      = binding.etUsername.text.toString().trim()
        val password = binding.etPassword.text.toString()

        if (idU.isEmpty()) {
            binding.etUsername.error = "Username required"
            return
        }
        if (password.isEmpty()) {
            binding.etPassword.error = "Password required"
            return
        }

        if (!keystoreManager.hasStoredR()) {
            showError("No account found on this device. Please register first.")
            return
        }

        startFingerprintLogin(idU, password)
    }

    // ─────────────────────────────────────────────────────────────
    // FINGERPRINT MODE (existing flow — unchanged)
    // ─────────────────────────────────────────────────────────────

    private fun startFingerprintLogin(idU: String, password: String) {
        setLoading(true, "Waiting for fingerprint...")

        val decryptCipher = try {
            keystoreManager.getDecryptCipher()
        } catch (e: Exception) {
            setLoading(false)
            showError("Keystore error: ${e.message}")
            return
        }

        keystoreManager.showBiometricPrompt(
            activity  = this,
            title     = "Authenticate",
            subtitle  = "Use your fingerprint to login",
            cipher    = decryptCipher,
            onSuccess = { authenticatedCipher ->
                val R = try {
                    keystoreManager.retrieveR(authenticatedCipher)
                } catch (e: Exception) {
                    setLoading(false)
                    showError("Failed to retrieve key: ${e.message}")
                    return@showBiometricPrompt
                }
                runAuthProtocol(idU, password, R)
            },
            onFailure = { error ->
                setLoading(false)
                showError(error)
            }
        )
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH PROTOCOL (shared by both modes)
    // ─────────────────────────────────────────────────────────────

    private fun runAuthProtocol(idU: String, password: String, R: ByteArray) {
        setLoading(true, "Starting TAKE Protocol...")

        lifecycleScope.launch {
            try {
                val sessionKey = executeAuthentication(idU, password, R, onProgress = { msg ->
                    withContext(Dispatchers.Main) {
                        setLoading(true, msg)
                    }
                })
                setLoading(false)
                showSuccess(sessionKey)

            } catch (e: Exception) {
                setLoading(false)
                val msg = e.message ?: e.toString()
                showError("Authentication failed: $msg")
            }
        }
    }

    private suspend fun executeAuthentication(
        idU: String,
        password: String,
        R: ByteArray,
        onProgress: suspend (String) -> Unit
    ): ByteArray {
        // Paper Section IV — Authentication and Key Exchange

        onProgress("Connecting to TAKE Server...")
        // Step 1: get P from server
        withContext(Dispatchers.IO) {
            apiClient.authInit(idU)
        }

        onProgress("Computing OPRF Blind Factor...")
        // Step 2: combined factor H0(pw || R)
        val cf = TakeCrypto.combinedFactor(password, R)

        // Step 3: blind combined factor + generate DH keypair
        val (blinded, rPrime) = TakeCrypto.oprfBlind(cf)
        val (x, X)            = TakeCrypto.dhKeygen()

        onProgress("Sending Diffie-Hellman Key X to Server...")
        // Step 4: send {IDU, H0(pw||R)^r', X} to server
        val oprfResult = withContext(Dispatchers.IO) {
            apiClient.authOprf(idU, blinded, X)
        }
        val Y          = oprfResult.Y
        val idS        = oprfResult.idS

        onProgress("Unblinding Server OPRF Response...")
        // Step 5: unblind → C' = H0(pw||R)^k1
        val cPrime = TakeCrypto.oprfUnblind(oprfResult.oprfResponse, rPrime)

        onProgress("Computing Shared DH Secret (Y^x)...")
        // Step 6: DH shared secret Y^x = g^xy
        val shared = TakeCrypto.dhShared(x, Y)

        onProgress("Verifying Server Authentication (σ1/σ2)...")
        val sigma1 = TakeCrypto.H3(
            TakeCrypto.concat(
                idU.toByteArray(),
                idS.toByteArray(),
                X, Y, shared, cPrime
            )
        )

        // Step 8: send σ1 to server, get σ2 back
        val sigma2FromServer = withContext(Dispatchers.IO) {
            apiClient.authVerify(idU, sigma1)
        }

        // Step 9: verify σ2 = H4(IDU || IDS || X || Y || Y^x || C')
        val sigma2Expected = TakeCrypto.H4(
            TakeCrypto.concat(
                idU.toByteArray(),
                idS.toByteArray(),
                X, Y, shared, cPrime
            )
        )

        if (!sigma2FromServer.contentEquals(sigma2Expected)) {
            throw Exception("Server authentication failed — σ2 mismatch. Possible MITM attack.")
        }

        // Step 10: compute session key SK = H5(IDU || IDS || X || Y || Y^x || C')
        return TakeCrypto.H5(
            TakeCrypto.concat(
                idU.toByteArray(),
                idS.toByteArray(),
                X, Y, shared, cPrime
            )
        )
    }



    // ─────────────────────────────────────────────────────────────
    // UI helpers
    // ─────────────────────────────────────────────────────────────

    private fun showSuccess(sessionKey: ByteArray) {
        val hex = sessionKey.joinToString("") { "%02x".format(it) }

        binding.tvStatus.text      = "Authenticated ✅"
        binding.tvSessionKey.text  = "Session key:\n${hex.take(32)}..."
        binding.tvSessionKey.visibility = View.VISIBLE

        binding.tvStatus.setTextColor(getColor(android.R.color.holo_green_dark))
        binding.cardResult.visibility = View.VISIBLE

        binding.tvTiming.text = "Protocol complete"
        binding.tvTiming.visibility = View.VISIBLE
    }

    private fun setLoading(loading: Boolean, message: String = "") {
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnLogin.isEnabled     = !loading
        if (message.isNotEmpty()) binding.tvStatus.text = message
    }

    private fun showError(message: String) {
        binding.tvStatus.text = message
        binding.tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
}
