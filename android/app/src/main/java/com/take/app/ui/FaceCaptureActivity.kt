package com.take.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Base64
import android.util.Size
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.facemesh.FaceMeshDetection
import com.google.mlkit.vision.facemesh.FaceMeshDetector
import com.take.app.R
import com.take.app.crypto.FaceCapture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView

/**
 * Camera activity for face biometric capture.
 * Opens front camera → detects face mesh → computes bitstring → returns result.
 *
 * Returns the 128-byte biometric bitstring via Intent extras:
 *   "bio_bitstring" → Base64-encoded 128-byte bitstring
 */
class FaceCaptureActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_BIO_BITSTRING = "bio_bitstring"
        const val REQUEST_CODE = 1001
        private const val CAMERA_PERMISSION_CODE = 100
    }

    private lateinit var previewView: PreviewView
    private lateinit var statusText: TextView
    private lateinit var cameraExecutor: ExecutorService
    private lateinit var faceMeshDetector: FaceMeshDetector

    private var captured = false  // Prevent multiple captures

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Build layout programmatically (no XML needed for this simple view)
        val rootLayout = FrameLayout(this).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        previewView = PreviewView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }
        rootLayout.addView(previewView)

        statusText = TextView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 48
                marginStart = 24
                marginEnd = 24
            }
            text = "Position your face in the frame..."
            textSize = 18f
            setTextColor(0xFFFFFFFF.toInt())
            setShadowLayer(4f, 2f, 2f, 0xFF000000.toInt())
            textAlignment = TextView.TEXT_ALIGNMENT_CENTER
        }
        rootLayout.addView(statusText)

        setContentView(rootLayout)

        cameraExecutor = Executors.newSingleThreadExecutor()
        faceMeshDetector = FaceCapture.createDetector()

        if (hasCameraPermission()) {
            startCamera()
        } else {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                CAMERA_PERMISSION_CODE
            )
        }
    }

    private fun hasCameraPermission(): Boolean =
        ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startCamera()
            } else {
                Toast.makeText(this, "Camera permission required for face scan", Toast.LENGTH_LONG).show()
                setResult(RESULT_CANCELED)
                finish()
            }
        }
    }

    @androidx.camera.core.ExperimentalGetImage
    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            // Preview
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            // Image analysis for face mesh detection
            val imageAnalysis = ImageAnalysis.Builder()
                .setTargetResolution(Size(640, 480))
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()

            imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                processImage(imageProxy)
            }

            // Use front camera
            val cameraSelector = CameraSelector.DEFAULT_FRONT_CAMERA

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(this, cameraSelector, preview, imageAnalysis)
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Camera init failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
                setResult(RESULT_CANCELED)
                finish()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    @androidx.camera.core.ExperimentalGetImage
    private fun processImage(imageProxy: ImageProxy) {
        if (captured) {
            imageProxy.close()
            return
        }

        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            imageProxy.close()
            return
        }

        val inputImage = InputImage.fromMediaImage(
            mediaImage,
            imageProxy.imageInfo.rotationDegrees
        )

        faceMeshDetector.process(inputImage)
            .addOnSuccessListener { faceMeshes ->
                if (faceMeshes.isNotEmpty() && !captured) {
                    val mesh = faceMeshes[0]
                    val meshPoints = mesh.allPoints

                    try {
                        val bitstring = FaceCapture.meshToBitstring(meshPoints)
                        captured = true

                        runOnUiThread {
                            statusText.text = "Face captured ✅"
                        }

                        // Return result after short delay for UX
                        previewView.postDelayed({
                            val resultIntent = Intent().apply {
                                putExtra(EXTRA_BIO_BITSTRING,
                                    Base64.encodeToString(bitstring, Base64.NO_WRAP))
                            }
                            setResult(RESULT_OK, resultIntent)
                            finish()
                        }, 500)

                    } catch (e: Exception) {
                        runOnUiThread {
                            statusText.text = "Detection error: ${e.message}\nKeep your face centered..."
                        }
                    }
                }
            }
            .addOnFailureListener { e ->
                // Silently continue — next frame will try again
            }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
        faceMeshDetector.close()
    }
}
