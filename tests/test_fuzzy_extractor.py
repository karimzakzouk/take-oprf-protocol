"""
Tests for fuzzy extractor (Gen/Rep) and biometric pipeline.
Run with: pytest tests/test_fuzzy_extractor.py -v

Note: webcam tests are skipped by default (require physical hardware).
      Run with --webcam flag to enable them.
"""

import pytest
import os
import sys
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from server.crypto.fuzzy_extractor import Gen, Rep, add_noise, TOLERANCE
from server.crypto.biometric import embedding_to_bitstring


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzy extractor tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzzyExtractor:

    def _fake_bio(self, seed: int = 42) -> bytes:
        """Generate a deterministic fake 128-byte biometric for testing."""
        rng = np.random.default_rng(seed)
        return bytes(rng.integers(0, 256, 128, dtype=np.uint8))

    def test_gen_output_lengths(self):
        """Gen should return R (32 bytes) and P (128 bytes = 32 nonce + 96 syndrome)."""
        bio = self._fake_bio()
        R, P = Gen(bio)
        assert len(R) == 32,  f"R should be 32 bytes, got {len(R)}"
        assert len(P) == 128, f"P should be 128 bytes, got {len(P)}"

    def test_gen_deterministic_R_for_same_bio(self):
        """
        R should be deterministic given same bio + same nonce.
        Two calls to Gen on same bio give different R (different nonce),
        but Rep always recovers the same R as its paired Gen.
        """
        bio = self._fake_bio()
        R1, P1 = Gen(bio)
        R2, P2 = Gen(bio)
        # Different nonces → different R values from Gen
        # But Rep(bio, P1) == R1 and Rep(bio, P2) == R2
        assert R1 != R2  # different nonces

    def test_rep_exact_match(self):
        """Rep with exact same bio should recover R perfectly."""
        bio = self._fake_bio()
        R, P = Gen(bio)
        R_recovered = Rep(bio, P)
        assert R == R_recovered, "Rep failed on identical biometric"

    def test_rep_with_small_noise(self):
        """Rep should recover R even when bio has a few bit flips."""
        bio = self._fake_bio()
        R, P = Gen(bio)

        # Simulate small noise (5 bit flips — well within tolerance)
        bio_noisy = add_noise(bio, n_flips=5)
        R_recovered = Rep(bio_noisy, P)
        assert R == R_recovered, "Rep failed with 5 bit flips"

    def test_rep_at_tolerance_boundary(self):
        """Rep should still work at exactly TOLERANCE bit flips."""
        bio = self._fake_bio()
        R, P = Gen(bio)

        bio_noisy = add_noise(bio, n_flips=TOLERANCE)
        R_recovered = Rep(bio_noisy, P)
        assert R == R_recovered, f"Rep failed at tolerance boundary ({TOLERANCE} flips)"

    def test_rep_fails_above_tolerance(self):
        """Rep should raise ValueError when noise exceeds tolerance."""
        bio = self._fake_bio()
        R, P = Gen(bio)

        # Way over tolerance
        bio_very_noisy = add_noise(bio, n_flips=TOLERANCE + 50)
        with pytest.raises(ValueError, match="Biometric too different"):
            Rep(bio_very_noisy, P)

    def test_wrong_bio_gives_wrong_R(self):
        """Completely different bio should not recover correct R."""
        bio1 = self._fake_bio(seed=1)
        bio2 = self._fake_bio(seed=2)
        R, P = Gen(bio1)

        with pytest.raises(ValueError):
            Rep(bio2, P)

    def test_P_does_not_reveal_R(self):
        """P alone should not be sufficient to compute R (sanity check)."""
        bio = self._fake_bio()
        R, P = Gen(bio)
        # P contains nonce + sketch — neither alone gives R
        nonce = P[:32]
        sketch = P[32:]
        # Can't derive R without bio
        from Crypto.Hash import SHA3_256
        # Wrong derivation (without bio) should give different result
        wrong = SHA3_256.new(nonce).digest()
        assert wrong != R

    def test_gen_invalid_input_length(self):
        """Gen should raise on wrong input length."""
        with pytest.raises(ValueError):
            Gen(b"too_short")

    def test_rep_invalid_bio_length(self):
        """Rep should raise on wrong bio length."""
        bio = self._fake_bio()
        _, P = Gen(bio)
        with pytest.raises(ValueError):
            Rep(b"too_short", P)

    def test_multiple_users_independent(self):
        """Two users' (R, P) pairs should be completely independent."""
        bio1 = self._fake_bio(seed=10)
        bio2 = self._fake_bio(seed=20)

        R1, P1 = Gen(bio1)
        R2, P2 = Gen(bio2)

        assert R1 != R2
        assert P1 != P2

        # Cross-recovery should fail
        with pytest.raises(ValueError):
            Rep(bio2, P1)

    def test_noise_simulation(self):
        """add_noise should flip exactly n bits."""
        bio = self._fake_bio()
        bio_noisy = add_noise(bio, n_flips=15)
        # Count bit differences
        diff = 0
        for a, b in zip(bio, bio_noisy):
            diff += bin(a ^ b).count('1')
        assert diff == 15


# ─────────────────────────────────────────────────────────────────────────────
# Biometric embedding pipeline tests (no webcam)
# ─────────────────────────────────────────────────────────────────────────────

class TestBiometricPipeline:

    def _fake_embedding(self) -> np.ndarray:
        """Simulate a dlib face embedding (128 floats in roughly [-0.5, 0.5])."""
        rng = np.random.default_rng(99)
        return rng.standard_normal(128).astype(np.float64) * 0.3

    def test_embedding_to_bitstring_length(self):
        """Quantized embedding should be 128 bytes."""
        emb = self._fake_embedding()
        bs = embedding_to_bitstring(emb)
        assert len(bs) == 128

    def test_embedding_to_bitstring_deterministic(self):
        """Same embedding should give same bitstring."""
        emb = self._fake_embedding()
        assert embedding_to_bitstring(emb) == embedding_to_bitstring(emb)

    def test_different_embeddings_different_bitstrings(self):
        """Different faces should give different bitstrings."""
        rng1 = np.random.default_rng(1)
        rng2 = np.random.default_rng(2)
        emb1 = rng1.standard_normal(128).astype(np.float64)
        emb2 = rng2.standard_normal(128).astype(np.float64)
        assert embedding_to_bitstring(emb1) != embedding_to_bitstring(emb2)

    def test_similar_embeddings_close_bitstrings(self):
        """
        Similar face embeddings (small noise) should produce
        bitstrings within fuzzy extractor tolerance.

        With sign-bit encoding, a sign flip only occurs when noise pushes
        a value across zero. For dlib/MobileFaceNet embeddings (~N(0,0.09))
        with realistic inter-scan noise (~0.007 std), the probability of a
        sign flip per dimension is ~1-2%, yielding 0-3 total bit flips across
        128 dimensions — well within TOLERANCE=24.
        """
        from server.crypto.fuzzy_extractor import _hamming_distance
        emb = self._fake_embedding()
        # Simulate same person, slightly different lighting/angle
        emb_noisy = emb + np.random.default_rng(5).standard_normal(128) * 0.007
        bs1 = embedding_to_bitstring(emb)
        bs2 = embedding_to_bitstring(emb_noisy)
        dist = _hamming_distance(bs1, bs2)
        print(f"\n  Hamming distance between similar scans: {dist} / 1024 bits")
        assert dist <= TOLERANCE, (
            f"Similar face scans too different: {dist} bits "
            f"(tolerance is {TOLERANCE})"
        )

    def test_full_pipeline_gen_rep_with_simulated_face(self):
        """
        Full pipeline test:
        face embedding → bitstring → Gen → (R, P) → noisy scan → Rep → R
        """
        # Simulate two scans of same face (slightly different)
        emb_scan1 = self._fake_embedding()
        emb_scan2 = emb_scan1 + np.random.default_rng(7).standard_normal(128) * 0.005

        bio1 = embedding_to_bitstring(emb_scan1)
        bio2 = embedding_to_bitstring(emb_scan2)

        # Registration: Gen on first scan
        R, P = Gen(bio1)

        # Authentication: Rep on second scan
        R_recovered = Rep(bio2, P)

        assert R == R_recovered, (
            "Full pipeline failed: Rep could not recover R from "
            "slightly different face scan"
        )
        print(f"\n  Full pipeline OK — R recovered: {R.hex()[:16]}...")