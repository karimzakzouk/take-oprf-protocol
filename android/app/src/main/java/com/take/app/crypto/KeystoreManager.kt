package com.take.app.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * KeystoreManager
 *
 * Stores and retrieves the secret R inside Android's hardware TEE.
 * R is protected by fingerprint authentication — only released when
 * the correct fingerprint is presented.
 *
 * This replaces the fuzzy extractor in our implementation.
 * Android Keystore = client-side TEE (equivalent to paper's TEE assumption).
 *
 * Uses AES-256-GCM for encrypting R, key is hardware-backed and
 * requires biometric authentication before each use.
 */
class KeystoreManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS         = "TAKE_R_KEY"
        private const val TRANSFORMATION    = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH    = 128
        private const val PREFS_NAME        = "take_prefs"
        private const val PREF_ENCRYPTED_R  = "encrypted_r"
        private const val PREF_IV           = "r_iv"
    }

    // ─────────────────────────────────────────────────────────────
    // Key generation — creates AES-256 key in hardware TEE
    // Requires biometric auth before every use (setUserAuthenticationRequired)
    // ─────────────────────────────────────────────────────────────

    fun generateKey() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)

        // Delete existing key if present
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // Require biometric auth before each use
            .setUserAuthenticationRequired(true)
            // Works with both fingerprint and other strong biometrics
            .setInvalidatedByBiometricEnrollment(true)
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    fun isKeyGenerated(): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore.containsAlias(KEY_ALIAS)
    }

    fun hasStoredR(): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(PREF_ENCRYPTED_R)
    }

    // ─────────────────────────────────────────────────────────────
    // Get encrypt cipher — for storing R (called before biometric prompt)
    // ─────────────────────────────────────────────────────────────

    fun getEncryptCipher(): Cipher {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        val key = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher
    }

    // ─────────────────────────────────────────────────────────────
    // Get decrypt cipher — for retrieving R (called before biometric prompt)
    // ─────────────────────────────────────────────────────────────

    fun getDecryptCipher(): Cipher {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ivB64 = prefs.getString(PREF_IV, null)
            ?: throw IllegalStateException("No IV stored — R was never saved")

        val iv = android.util.Base64.decode(ivB64, android.util.Base64.NO_WRAP)

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        val key = keyStore.getKey(KEY_ALIAS, null) as SecretKey

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        return cipher
    }

    // ─────────────────────────────────────────────────────────────
    // Store R — called after biometric auth succeeds (encrypt mode)
    // ─────────────────────────────────────────────────────────────

    fun storeR(R: ByteArray, authenticatedCipher: Cipher) {
        val encrypted = authenticatedCipher.doFinal(R)
        val iv = authenticatedCipher.iv

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(PREF_ENCRYPTED_R,
                android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
            .putString(PREF_IV,
                android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
            .apply()
    }

    // ─────────────────────────────────────────────────────────────
    // Retrieve R — called after biometric auth succeeds (decrypt mode)
    // ─────────────────────────────────────────────────────────────

    fun retrieveR(authenticatedCipher: Cipher): ByteArray {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedB64 = prefs.getString(PREF_ENCRYPTED_R, null)
            ?: throw IllegalStateException("No R stored")

        val encrypted = android.util.Base64.decode(encryptedB64, android.util.Base64.NO_WRAP)
        return authenticatedCipher.doFinal(encrypted)
    }

    // ─────────────────────────────────────────────────────────────
    // Show biometric prompt
    // ─────────────────────────────────────────────────────────────

    fun showBiometricPrompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        cipher: Cipher,
        onSuccess: (Cipher) -> Unit,
        onFailure: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(
                result: BiometricPrompt.AuthenticationResult
            ) {
                val authenticatedCipher = result.cryptoObject?.cipher
                    ?: run { onFailure("No cipher returned"); return }
                onSuccess(authenticatedCipher)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onFailure("Biometric error: $errString")
            }

            override fun onAuthenticationFailed() {
                onFailure("Fingerprint not recognised — try again")
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .build()

        prompt.authenticate(
            promptInfo,
            BiometricPrompt.CryptoObject(cipher)
        )
    }

    // ─────────────────────────────────────────────────────────────
    // Clear stored data (for logout / re-registration)
    // ─────────────────────────────────────────────────────────────

    fun clearStoredData() {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }
}
