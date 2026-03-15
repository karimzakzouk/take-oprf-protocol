package com.take.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.Rect
import android.graphics.YuvImage
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
import com.google.mlkit.vision.face.FaceDetection
import com.google.mlkit.vision.face.FaceDetector
import com.google.mlkit.vision.face.FaceDetectorOptions
import com.take.app.crypto.FaceCapture
import java.io.ByteArrayOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView

/**
 * Camera activity for face biometric capture.
 * Opens front camera → detects face → crops → runs MobileFaceNet →
 * returns 128-byte biometric bitstring via Intent extras.
 *
 * Returns:
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
    private lateinit var faceDetector: FaceDetector

    private var captured = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize MobileFaceNet
        FaceCapture.init(this)

        // Build layout programmatically
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

        // ML Kit Face Detection (just for bounding box — not mesh)
        val options = FaceDetectorOptions.Builder()
            .setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_FAST)
            .setMinFaceSize(0.3f)
            .build()
        faceDetector = FaceDetection.getClient(options)

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

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            val imageAnalysis = ImageAnalysis.Builder()
                .setTargetResolution(Size(640, 480))
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()

            imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                processImage(imageProxy)
            }

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

        faceDetector.process(inputImage)
            .addOnSuccessListener { faces ->
                if (faces.isNotEmpty() && !captured) {
                    val face = faces[0]
                    val bounds = face.boundingBox

                    try {
                        // Convert ImageProxy to Bitmap
                        val bitmap = imageProxyToBitmap(imageProxy)
                        if (bitmap != null) {
                            // Crop face region with some padding
                            val cropped = cropFace(bitmap, bounds)
                            if (cropped != null) {
                                // Run MobileFaceNet to get 128-byte bitstring
                                val bitstring = FaceCapture.bitmapToBitstring(cropped)
                                captured = true

                                runOnUiThread {
                                    statusText.text = "Face captured ✅"
                                }

                                previewView.postDelayed({
                                    val resultIntent = Intent().apply {
                                        putExtra(EXTRA_BIO_BITSTRING,
                                            Base64.encodeToString(bitstring, Base64.NO_WRAP))
                                    }
                                    setResult(RESULT_OK, resultIntent)
                                    finish()
                                }, 500)
                            }
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            statusText.text = "Detection error: ${e.message}\nKeep your face centered..."
                        }
                    }
                }
            }
            .addOnFailureListener { /* next frame will retry */ }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }

    /**
     * Convert ImageProxy (YUV_420_888) to Bitmap.
     */
    @androidx.camera.core.ExperimentalGetImage
    private fun imageProxyToBitmap(imageProxy: ImageProxy): Bitmap? {
        val image = imageProxy.image ?: return null
        val yBuffer = image.planes[0].buffer
        val uBuffer = image.planes[1].buffer
        val vBuffer = image.planes[2].buffer

        val ySize = yBuffer.remaining()
        val uSize = uBuffer.remaining()
        val vSize = vBuffer.remaining()

        val nv21 = ByteArray(ySize + uSize + vSize)
        yBuffer.get(nv21, 0, ySize)
        vBuffer.get(nv21, ySize, vSize)
        uBuffer.get(nv21, ySize + vSize, uSize)

        val yuvImage = YuvImage(nv21, ImageFormat.NV21, image.width, image.height, null)
        val out = ByteArrayOutputStream()
        yuvImage.compressToJpeg(Rect(0, 0, image.width, image.height), 90, out)
        val bytes = out.toByteArray()

        var bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return null

        // Apply rotation
        val rotation = imageProxy.imageInfo.rotationDegrees
        if (rotation != 0) {
            val matrix = Matrix()
            matrix.postRotate(rotation.toFloat())
            bitmap = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true)
        }

        return bitmap
    }

    /**
     * Crop face from bitmap with 20% padding around bounding box.
     */
    private fun cropFace(bitmap: Bitmap, bounds: Rect): Bitmap? {
        val padding = (bounds.width() * 0.2).toInt()

        val left   = maxOf(0, bounds.left - padding)
        val top    = maxOf(0, bounds.top - padding)
        val right  = minOf(bitmap.width, bounds.right + padding)
        val bottom = minOf(bitmap.height, bounds.bottom + padding)

        val width = right - left
        val height = bottom - top

        if (width <= 0 || height <= 0) return null

        return Bitmap.createBitmap(bitmap, left, top, width, height)
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
        faceDetector.close()
    }
}
