"""
TAKE Face Biometric Module
Captures face embedding from webcam using dlib.
Produces a 128-dimensional float vector that serves as `bio` in the paper.
"""

import cv2
import dlib
import numpy as np
import os

# ─────────────────────────────────────────────────────────────────────────────
# Model paths — dlib needs two pretrained model files
# Download instructions printed if missing
# ─────────────────────────────────────────────────────────────────────────────

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
SHAPE_PREDICTOR_PATH = os.path.join(MODELS_DIR, "shape_predictor_68_face_landmarks.dat")
FACE_REC_MODEL_PATH  = os.path.join(MODELS_DIR, "dlib_face_recognition_resnet_model_v1.dat")


def check_models():
    """Check if dlib model files exist, print download instructions if not."""
    missing = []
    if not os.path.exists(SHAPE_PREDICTOR_PATH):
        missing.append("shape_predictor_68_face_landmarks.dat")
    if not os.path.exists(FACE_REC_MODEL_PATH):
        missing.append("dlib_face_recognition_resnet_model_v1.dat")

    if missing:
        print("\n[ERROR] Missing dlib model files:")
        for m in missing:
            print(f"  - {m}")
        print("\nDownload them with:")
        print(f"  mkdir -p {MODELS_DIR}")
        print(f"  cd {MODELS_DIR}")
        print("  wget http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2")
        print("  wget http://dlib.net/files/dlib_face_recognition_resnet_model_v1.dat.bz2")
        print("  bzip2 -d shape_predictor_68_face_landmarks.dat.bz2")
        print("  bzip2 -d dlib_face_recognition_resnet_model_v1.dat.bz2")
        raise FileNotFoundError(f"Missing model files: {missing}")


# ─────────────────────────────────────────────────────────────────────────────
# Load models (lazy — only when first needed)
# ─────────────────────────────────────────────────────────────────────────────

_detector  = None
_predictor = None
_face_rec  = None


def _load_models():
    global _detector, _predictor, _face_rec
    if _detector is None:
        check_models()
        print("[biometric] Loading dlib models...")
        _detector  = dlib.get_frontal_face_detector()
        _predictor = dlib.shape_predictor(SHAPE_PREDICTOR_PATH)
        _face_rec  = dlib.face_recognition_model_v1(FACE_REC_MODEL_PATH)
        print("[biometric] Models loaded.")


# ─────────────────────────────────────────────────────────────────────────────
# Core: capture face embedding from webcam
# ─────────────────────────────────────────────────────────────────────────────

def capture_face_embedding(camera_index: int = 0,
                           timeout_seconds: int = 15) -> np.ndarray:
    """
    Open webcam, detect face, extract 128-dim embedding.

    Returns:
        np.ndarray of shape (128,) — float64 face embedding

    Raises:
        RuntimeError if no face detected within timeout
    """
    _load_models()

    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        raise RuntimeError("Cannot open webcam")

    print("[biometric] Look at the camera... (press Q to cancel)")

    start = cv2.getTickCount()
    embedding = None

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Check timeout
        elapsed = (cv2.getTickCount() - start) / cv2.getTickFrequency()
        if elapsed > timeout_seconds:
            break

        # Detect faces
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        faces = _detector(rgb, 1)

        if len(faces) > 0:
            face = faces[0]
            shape = _predictor(rgb, face)
            embedding = np.array(
                _face_rec.compute_face_descriptor(rgb, shape)
            )
            # Draw box on detected face
            cv2.rectangle(frame,
                (face.left(), face.top()),
                (face.right(), face.bottom()),
                (0, 255, 0), 2)
            cv2.putText(frame, "Face detected - capturing...",
                (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,0), 2)

        cv2.imshow("TAKE - Face Scan (press Q to cancel)", frame)

        # If we got an embedding, show it briefly then close
        if embedding is not None:
            cv2.waitKey(500)
            break

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

    if embedding is None:
        raise RuntimeError("No face detected. Ensure good lighting and face the camera.")

    print(f"[biometric] Embedding captured. Shape: {embedding.shape}")
    return embedding


# ─────────────────────────────────────────────────────────────────────────────
# Fixed-range quantization
#
# WHY fixed range instead of per-sample min/max:
#   dlib face embeddings are L2-normalized unit vectors.
#   Their values are bounded to roughly [-0.5, 0.5].
#   If we use per-sample min/max normalization, a tiny change in
#   one outlier value shifts the entire scale → hundreds of bit flips
#   from a trivially different scan. Fixed range keeps the mapping
#   stable across scans of the same face.
#
# We clip to [-0.6, 0.6] (covers >99.9% of real dlib values)
# then map to [0, 255] — 8 bits per dimension = 1024 bits total.
# ─────────────────────────────────────────────────────────────────────────────

EMBED_MIN   = -0.6
EMBED_MAX   =  0.6
EMBED_RANGE = EMBED_MAX - EMBED_MIN  # 1.2


def embedding_to_bitstring(embedding: np.ndarray) -> bytes:
    """
    Convert 128-dim float embedding to a fixed-length 128-byte bitstring.
    Uses a fixed quantization range — NOT per-sample min/max.

    This is the `bio` input to the fuzzy extractor.
    """
    # Clip to expected dlib range
    clipped = np.clip(embedding, EMBED_MIN, EMBED_MAX)

    # Map [-0.6, 0.6] → [0, 255] with fixed scale
    normalized = (clipped - EMBED_MIN) / EMBED_RANGE
    quantized = (normalized * 255).astype(np.uint8)

    return bytes(quantized)


def get_face_bitstring(camera_index: int = 0) -> bytes:
    """
    Full pipeline: webcam → face detection → embedding → bitstring.
    This is what you call to get `bio` for the fuzzy extractor.
    """
    embedding = capture_face_embedding(camera_index)
    return embedding_to_bitstring(embedding)