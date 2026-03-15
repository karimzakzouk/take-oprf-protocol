#!/bin/bash
# Download dlib model files required by server/crypto/biometric.py

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Downloading dlib model files to $SCRIPT_DIR ..."

# Shape predictor (68 facial landmarks)
if [ ! -f "shape_predictor_68_face_landmarks.dat" ]; then
    echo "  Downloading shape_predictor_68_face_landmarks.dat ..."
    wget -q http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2
    bzip2 -d shape_predictor_68_face_landmarks.dat.bz2
    echo "  ✓ Done"
else
    echo "  ✓ shape_predictor_68_face_landmarks.dat already exists"
fi

# Face recognition model (ResNet)
if [ ! -f "dlib_face_recognition_resnet_model_v1.dat" ]; then
    echo "  Downloading dlib_face_recognition_resnet_model_v1.dat ..."
    wget -q http://dlib.net/files/dlib_face_recognition_resnet_model_v1.dat.bz2
    bzip2 -d dlib_face_recognition_resnet_model_v1.dat.bz2
    echo "  ✓ Done"
else
    echo "  ✓ dlib_face_recognition_resnet_model_v1.dat already exists"
fi

echo ""
echo "All models ready!"
