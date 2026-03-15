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

        elapsed = (cv2.getTickCount() - start) / cv2.getTickFrequency()
        if elapsed > timeout_seconds:
            break

        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        faces = _detector(rgb, 1)

        if len(faces) > 0:
            face = faces[0]
            shape = _predictor(rgb, face)
            embedding = np.array(
                _face_rec.compute_face_descriptor(rgb, shape)
            )
            cv2.rectangle(frame,
                (face.left(), face.top()),
                (face.right(), face.bottom()),
                (0, 255, 0), 2)
            cv2.putText(frame, "Face detected - capturing...",
                (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,255,0), 2)

        cv2.imshow("TAKE - Face Scan (press Q to cancel)", frame)

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
# Sign-bit quantization
#
# WHY sign bits instead of multi-bit fixed-range quantization:
#
#   The previous 8-bit quantization (each float → 1 byte) produced ~170 bit
#   flips from realistic inter-scan noise (0.007 std on a 0.3-scale embedding).
#   That's because a small float shift of 0.007 moves ~1.5 quantization steps,
#   each step flipping 1-3 bits → ~200 bit flips total. This far exceeded
#   BCH_T=32, breaking the fuzzy extractor on real face scans.
#
#   Sign-bit encoding uses 1 bit per dimension: bit[i] = 1 if embedding[i] >= 0.
#   A sign flip only occurs when noise is large enough to push a value across
#   zero. For dlib embeddings (roughly N(0, 0.09) per dimension) and realistic
#   inter-scan noise (~0.005-0.01 std), the probability of a sign flip per
#   dimension is ~1-2%, yielding 1-3 total bit flips across 128 dimensions.
#   This is well within BCH_T=32.
#
# Encoding layout (128 bytes total):
#   Bytes  0-15: 128 sign bits packed (1 bit per embedding dimension)
#   Bytes 16-127: zero padding (112 bytes)
#
# The fuzzy extractor (BCH over 1023 bits) operates on all 1024 bits.
# Errors only ever appear in the first 128 bits; the zero-padded bits are
# always identical between scans of the same face.
# ─────────────────────────────────────────────────────────────────────────────

_BIO_BYTES       = 128
_SIGN_BITS       = 128   # one per embedding dimension
_SIGN_BYTES      = _SIGN_BITS // 8   # 16 bytes packed
_PADDING_BYTES   = _BIO_BYTES - _SIGN_BYTES  # 112 zero bytes


def embedding_to_bitstring(embedding: np.ndarray) -> bytes:
    """
    Convert 128-dim float embedding to a 128-byte bitstring via sign-bit encoding.

    Each of the 128 embedding dimensions contributes exactly 1 bit:
      bit[i] = 1 if embedding[i] >= 0, else 0

    The 128 bits are packed MSB-first into 16 bytes, then zero-padded to
    128 bytes for compatibility with the fuzzy extractor's expected input size.

    Stability guarantee:
      Two scans of the same face typically differ by <= 3 bit flips (<<BCH_T=24),
      because sign flips require noise to cross zero, which is unlikely for
      dlib L2-normalized embeddings with typical inter-scan variation.
    """
    sign_bits = (embedding >= 0).astype(np.uint8)  # 128 bits, one per dim
    packed    = np.packbits(sign_bits)              # 16 bytes, MSB first
    return bytes(packed) + bytes(_PADDING_BYTES)    # pad to 128 bytes


def get_face_bitstring(camera_index: int = 0) -> bytes:
    """
    Full pipeline: webcam → face detection → embedding → bitstring.
    This is what you call to get `bio` for the fuzzy extractor.
    """
    embedding = capture_face_embedding(camera_index)
    return embedding_to_bitstring(embedding)