package com.take.app.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.take.app.R
import com.take.app.crypto.FuzzyExtractor
import com.take.app.crypto.KeystoreManager
import com.take.app.crypto.TakeCrypto
import com.take.app.databinding.ActivityRegisterBinding
import com.take.app.network.TakeApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.security.MessageDigest
import java.math.BigInteger

/**
 * Registration screen with Fingerprint / Face toggle.
 *
 * FINGERPRINT mode:
 *   R = random 32 bytes, stored in Android Keystore (hardware TEE).
 *   P = dummy 160 zero bytes (no fuzzy extractor needed).
 *
 * FACE mode (paper-faithful):
 *   Camera captures face → MobileFaceNet embedding → 128-byte bio.
 *   Gen(bio) → (R, P). Both R and P are real cryptographic values.
 *   R is used immediately for OPRF, P is sent to server.
 *   This matches Section IV of the TAKE paper exactly.
 */
class RegisterActivity : AppCompatActivity() {

    private lateinit var binding: ActivityRegisterBinding
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var apiClient: TakeApiClient

    private var pendingR: ByteArray? = null
    private var pendingP: ByteArray? = null
    private var isFaceMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRegisterBinding.inflate(layoutInflater)
        setContentView(binding.root)

        keystoreManager = KeystoreManager(this)
        apiClient = TakeApiClient(getServerUrl())

        binding.toggleBioMode.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (isChecked) {
                isFaceMode = (checkedId == R.id.btnFaceMode)
            }
        }

        binding.btnRegister.setOnClickListener { startRegistration() }
        binding.btnGoToLogin.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java))
        }
    }

    private fun startRegistration() {
        val idU      = binding.etUsername.text.toString().trim()
        val password = binding.etPassword.text.toString()
        val confirm  = binding.etConfirmPassword.text.toString()

        if (idU.isEmpty()) {
            binding.etUsername.error = "Username required"
            return
        }
        if (password.length < 6) {
            binding.etPassword.error = "Password must be at least 6 characters"
            return
        }
        if (password != confirm) {
            binding.etConfirmPassword.error = "Passwords do not match"
            return
        }

        if (isFaceMode) {
            startFaceRegistration(idU, password)
        } else {
            startFingerprintRegistration(idU, password)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // FINGERPRINT MODE (Keystore TEE — unchanged)
    // ─────────────────────────────────────────────────────────────

    private fun startFingerprintRegistration(idU: String, password: String) {
        setLoading(true, "Generating your secret key...")

        val R = ByteArray(32).also { SecureRandom().nextBytes(it) }
        pendingR = R
        pendingP = ByteArray(128)  // dummy P for fingerprint mode

        keystoreManager.generateKey()

        val encryptCipher = try {
            keystoreManager.getEncryptCipher()
        } catch (e: Exception) {
            setLoading(false)
            showError("Keystore error: ${e.message}")
            return
        }

        setLoading(false)
        binding.tvStatus.text = "Press your fingerprint to secure your key"

        keystoreManager.showBiometricPrompt(
            activity  = this,
            title     = "Secure your account",
            subtitle  = "Your fingerprint will protect your secret key",
            cipher    = encryptCipher,
            onSuccess = { authenticatedCipher ->
                keystoreManager.storeR(R, authenticatedCipher)
                runRegistrationProtocol(idU, password, R, pendingP!!)
            },
            onFailure = { error ->
                setLoading(false)
                showError(error)
            }
        )
    }

    // ─────────────────────────────────────────────────────────────
    // FACE MODE (Paper-faithful: Gen(bio) → R, P)
    // ─────────────────────────────────────────────────────────────

    private fun startFaceRegistration(idU: String, password: String) {
        setLoading(true, "Opening camera for face scan...")

        // Save credentials for use after camera returns
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putString("pending_id_u", idU)
            .putString("pending_password", password)
            .apply()

        // Launch face capture activity
        @Suppress("DEPRECATION")
        startActivityForResult(
            Intent(this, FaceCaptureActivity::class.java),
            FaceCaptureActivity.REQUEST_CODE
        )
    }

    @Deprecated("Using deprecated API for simplicity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == FaceCaptureActivity.REQUEST_CODE) {
            if (resultCode == RESULT_OK && data != null) {
                val bioB64 = data.getStringExtra(FaceCaptureActivity.EXTRA_BIO_BITSTRING)
                if (bioB64 != null) {
                    val bio = Base64.decode(bioB64, Base64.NO_WRAP)
                    processFaceRegistration(bio)
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

    private fun processFaceRegistration(bio: ByteArray) {
        setLoading(true, "Running Fuzzy Extractor Gen(bio)...")

        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val idU      = prefs.getString("pending_id_u", "") ?: ""
        val password = prefs.getString("pending_password", "") ?: ""

        // Paper Section IV: Gen(bio) → (R, P)
        val genResult = FuzzyExtractor.Gen(bio)
        val R = genResult.R
        val P = genResult.P

        pendingR = R
        pendingP = P

        binding.tvStatus.text = "Face captured ✅ — Gen(bio) complete\nR: ${R.size} bytes, P: ${P.size} bytes"

        runRegistrationProtocol(idU, password, R, P)
    }

    // ─────────────────────────────────────────────────────────────
    // OPRF registration protocol (shared by both modes)
    // ─────────────────────────────────────────────────────────────

    private fun runRegistrationProtocol(idU: String, password: String, R: ByteArray, P: ByteArray) {
        setLoading(true, "Registering with server...")

        lifecycleScope.launch {
            try {
                executeRegistration(idU, password, R, P) { msg ->
                    withContext(Dispatchers.Main) {
                        setLoading(true, msg)
                    }
                }
                setLoading(false)
                binding.tvStatus.text = "Registration complete ✅"
                binding.tvStatus.setTextColor(getColor(android.R.color.holo_green_dark))

                binding.root.postDelayed({
                    startActivity(Intent(this@RegisterActivity, LoginActivity::class.java))
                    finish()
                }, 1500)

            } catch (e: Exception) {
                setLoading(false)
                val msg = e.message ?: e.toString()
                showError("Registration failed: $msg")
            }
        }
    }

    private suspend fun executeRegistration(
        idU: String,
        password: String,
        R: ByteArray,
        P: ByteArray,
        onProgress: suspend (String) -> Unit
    ) {
        // Paper Section IV — Registration

        onProgress("Computing Combined Factor H0(pw || R)...")
        val cf = TakeCrypto.combinedFactor(password, R)

        onProgress("Blinding Factor for OPRF...")
        val (blinded, r) = TakeCrypto.oprfBlind(cf)

        onProgress("Sending Blinded Factor to Server...")
        val oprfResponse = withContext(Dispatchers.IO) {
            apiClient.registerInit(idU, blinded)
        }

        onProgress("Unblinding Server OPRF Response...")
        val C = TakeCrypto.oprfUnblind(oprfResponse, r)

        val pwHash = MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray())
            .joinToString("") { "%02x".format(it) }

        onProgress("Finalizing Registration with Server...")
        withContext(Dispatchers.IO) {
            apiClient.registerFinalize(idU, P, C, pwHash)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Server URL configuration
    // ─────────────────────────────────────────────────────────────

    private fun getServerUrl(): String {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString("server_url", DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL
    }

    // ─────────────────────────────────────────────────────────────
    // UI helpers
    // ─────────────────────────────────────────────────────────────

    private fun setLoading(loading: Boolean, message: String = "") {
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnRegister.isEnabled  = !loading
        if (message.isNotEmpty()) binding.tvStatus.text = message
    }

    private fun showError(message: String) {
        setLoading(false)
        binding.tvStatus.text = message
        binding.tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        const val DEFAULT_SERVER_URL = "http://100.53.228.140:5000"
        const val PREFS_NAME = "take_prefs"
        const val PREF_BIO_MODE = "bio_mode"
    }
}
