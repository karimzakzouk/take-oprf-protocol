package com.take.app.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.take.app.R
import com.take.app.crypto.FuzzyExtractor
import com.take.app.crypto.KeystoreManager
import com.take.app.crypto.TakeCrypto
import com.take.app.databinding.ActivityLoginBinding
import com.take.app.network.TakeApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigInteger

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

    private var isFaceMode = false
    private var pendingHelperP: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        keystoreManager = KeystoreManager(this)
        apiClient = TakeApiClient(getServerUrl())

        binding.toggleBioMode.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                isFaceMode = (checkedId == R.id.btnFaceMode)
            }
        }

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

        if (isFaceMode) {
            startFaceLogin(idU, password)
        } else {
            if (!keystoreManager.hasStoredR()) {
                showError("No account found on this device. Please register first.")
                return
            }
            startFingerprintLogin(idU, password)
        }
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
    // FACE MODE (paper-faithful: authInit → P → camera → Rep → R)
    // ─────────────────────────────────────────────────────────────

    private fun startFaceLogin(idU: String, password: String) {
        setLoading(true, "Retrieving helper string P from server...")

        // Save credentials for after camera returns
        getSharedPreferences(RegisterActivity.PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString("pending_id_u", idU)
            .putString("pending_password", password)
            .apply()

        lifecycleScope.launch {
            try {
                // Paper: S retrieves P according to IDU and returns it to U
                val helperP = withContext(Dispatchers.IO) {
                    apiClient.authInit(idU)
                }
                pendingHelperP = helperP

                withContext(Dispatchers.Main) {
                    setLoading(true, "Opening camera for face scan...")
                }

                // Launch face capture activity
                @Suppress("DEPRECATION")
                startActivityForResult(
                    Intent(this@LoginActivity, FaceCaptureActivity::class.java),
                    FaceCaptureActivity.REQUEST_CODE
                )

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    showError("Failed to get helper P: ${e.message}")
                }
            }
        }
    }

    @Deprecated("Using deprecated API for simplicity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == FaceCaptureActivity.REQUEST_CODE) {
            if (resultCode == RESULT_OK && data != null) {
                val bioB64 = data.getStringExtra(FaceCaptureActivity.EXTRA_BIO_BITSTRING)
                if (bioB64 != null) {
                    val bio = Base64.decode(bioB64, Base64.NO_WRAP)
                    processFaceLogin(bio)
                } else {
                    setLoading(false)
                    showError("Face capture returned no data")
                }
            } else {
                setLoading(false)
                showError("Face capture cancelled")
            }
        }
    }

    private fun processFaceLogin(bio: ByteArray) {
        val P = pendingHelperP
        if (P == null) {
            showError("No helper string P. Try again.")
            return
        }

        setLoading(true, "Running Fuzzy Extractor Rep(bio', P)...")

        val prefs = getSharedPreferences(RegisterActivity.PREFS_NAME, Context.MODE_PRIVATE)
        val idU      = prefs.getString("pending_id_u", "") ?: ""
        val password = prefs.getString("pending_password", "") ?: ""

        // Paper Section IV: U executes Rep(bio, P) to recover R
        val R: ByteArray
        try {
            R = FuzzyExtractor.Rep(bio, P)
        } catch (e: IllegalArgumentException) {
            showError("Face not recognised — Rep(bio', P) failed.\n${e.message}")
            return
        }

        binding.tvStatus.text = "Face recognised ✅ — Rep(bio', P) recovered R"
        runAuthProtocol(idU, password, R)
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
        // In face mode, we already called authInit to get P.
        // In fingerprint mode, we still call it for protocol completeness.
        if (!isFaceMode) {
            withContext(Dispatchers.IO) {
                apiClient.authInit(idU)
            }
        }

        onProgress("Computing OPRF Blind Factor...")
        val cf = TakeCrypto.combinedFactor(password, R)

        val (blinded, rPrime) = TakeCrypto.oprfBlind(cf)
        val (x, X)            = TakeCrypto.dhKeygen()

        onProgress("Sending Diffie-Hellman Key X to Server...")
        val oprfResult = withContext(Dispatchers.IO) {
            apiClient.authOprf(idU, blinded, X)
        }
        val Y          = oprfResult.Y
        val idS        = oprfResult.idS

        onProgress("Unblinding Server OPRF Response...")
        val cPrime = TakeCrypto.oprfUnblind(oprfResult.oprfResponse, rPrime)

        onProgress("Computing Shared DH Secret (Y^x)...")
        val shared = TakeCrypto.dhShared(x, Y)

        onProgress("Verifying Server Authentication (σ1/σ2)...")
        val sigma1 = TakeCrypto.H3(
            TakeCrypto.concat(
                idU.toByteArray(),
                idS.toByteArray(),
                X, Y, shared, cPrime
            )
        )

        val sigma2FromServer = withContext(Dispatchers.IO) {
            apiClient.authVerify(idU, sigma1)
        }

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

        return TakeCrypto.H5(
            TakeCrypto.concat(
                idU.toByteArray(),
                idS.toByteArray(),
                X, Y, shared, cPrime
            )
        )
    }

    // ─────────────────────────────────────────────────────────────
    // Server URL
    // ─────────────────────────────────────────────────────────────

    private fun getServerUrl(): String {
        val prefs = getSharedPreferences(RegisterActivity.PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString("server_url", RegisterActivity.DEFAULT_SERVER_URL)
            ?: RegisterActivity.DEFAULT_SERVER_URL
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
        setLoading(false)
        binding.tvStatus.text = message
        binding.tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }
}
