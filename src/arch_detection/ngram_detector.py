"""
N-gram based ML classifier for architecture detection.
Uses byte n-gram frequency features with Random Forest classifier.
"""
import os
import math
import pickle
from typing import List
from collections import Counter
from .base import BaseDetector, ArchDetectionResult

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class NgramDetector(BaseDetector):
    """
    ML-based architecture detection using byte n-gram frequencies.
    
    Method: Extract n-gram frequency features from binary,
    classify using pre-trained Random Forest model.
    """
    
    name = "ngram_ml"
    weight = 2.0  # ML is robust to variations
    
    NGRAM_SIZE = 3
    FEATURE_SIZE = 1000  # Top 1000 n-gram features
    SAMPLE_SIZE = 50000  # First 50KB
    
    # Architecture labels
    LABELS = ["ARM32", "ARM64", "ARM-Thumb", "x86", "x86-64", 
              "MIPS-BE", "MIPS-LE", "RISCV32", "PowerPC", "Unknown"]
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)
        else:
            # Use heuristic fallback based on known n-gram patterns
            self.model = None
    
    def _load_model(self, path: str):
        """Load trained model from disk."""
        try:
            with open(path, "rb") as f:
                self.model = pickle.load(f)
        except Exception:
            self.model = None
    
    def is_available(self) -> bool:
        return ML_AVAILABLE
    
    def _extract_ngrams(self, data: bytes) -> Counter:
        """Extract n-gram counts from binary data."""
        sample = data[:self.SAMPLE_SIZE]
        ngrams = Counter()
        
        for i in range(len(sample) - self.NGRAM_SIZE + 1):
            ngram = sample[i:i + self.NGRAM_SIZE]
            ngrams[ngram] += 1
        
        return ngrams
    
    def _extract_features(self, data: bytes) -> 'np.ndarray':
        """Extract feature vector from n-grams."""
        ngrams = self._extract_ngrams(data)
        total = sum(ngrams.values())
        
        if not ML_AVAILABLE:
            return None
        
        # Convert to normalized frequency vector
        features = np.zeros(self.FEATURE_SIZE)
        for idx, (ngram, count) in enumerate(ngrams.most_common(self.FEATURE_SIZE)):
            features[idx] = count / total if total > 0 else 0
        
        return features.reshape(1, -1)
    
    def _heuristic_detect(self, data: bytes) -> List[ArchDetectionResult]:
        """
        Heuristic detection based on known n-gram patterns.
        Used when ML model is not available.
        """
        ngrams = self._extract_ngrams(data)
        
        # Known architecture n-gram signatures
        SIGNATURES = {
            "ARM32": [b'\xe5\x2d\xe9', b'\xe8\xbd', b'\xe3\xa0'],
            "ARM-Thumb": [b'\x80\xb5', b'\xf0\xb5', b'\xbd\xe8'],
            "ARM64": [b'\xfd\x7b', b'\xf9\x00', b'\x91\x00'],
            "x86": [b'\x55\x89\xe5', b'\x83\xec', b'\x8b\x45'],
            "MIPS-BE": [b'\x27\xbd', b'\xaf\xbf', b'\x8f\xbf'],
            "MIPS-LE": [b'\xbd\x27', b'\xbf\xaf', b'\xbf\x8f'],
        }
        
        scores = {}
        for arch, patterns in SIGNATURES.items():
            score = sum(ngrams.get(p, 0) for p in patterns)
            if score > 0:
                scores[arch] = score
        
        if not scores:
            return [ArchDetectionResult(
                architecture="Unknown",
                confidence=0.3,
                method=self.name,
                details={"heuristic": True}
            )]
        
        # Normalize scores
        max_score = max(scores.values())
        results = []
        for arch, score in scores.items():
            confidence = min(score / max_score * 0.8, 0.9)  # Cap at 0.9 for heuristic
            results.append(ArchDetectionResult(
                architecture=arch,
                confidence=confidence,
                bits=64 if "64" in arch else 32,
                endian="BE" if "BE" in arch else "LE",
                method=self.name,
                details={"heuristic": True, "raw_score": score}
            ))
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
    
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """Run ML-based detection."""
        
        # If model not available, use heuristic
        if self.model is None or not ML_AVAILABLE:
            return self._heuristic_detect(data)
        
        features = self._extract_features(data)
        
        try:
            probs = self.model.predict_proba(features)[0]
            pred_idx = probs.argmax()
            pred_label = self.LABELS[pred_idx] if pred_idx < len(self.LABELS) else "Unknown"
            
            results = [ArchDetectionResult(
                architecture=pred_label,
                confidence=float(probs[pred_idx]),
                bits=64 if "64" in pred_label else 32,
                endian="BE" if "BE" in pred_label else "LE",
                method=self.name,
                details={
                    "probabilities": dict(zip(self.LABELS, [float(p) for p in probs])),
                    "model": True
                }
            )]
            
            return results
            
        except Exception as e:
            return self._heuristic_detect(data)


class NgramModelTrainer:
    """Utility class to train n-gram model."""
    
    NGRAM_SIZE = 3
    FEATURE_SIZE = 1000
    SAMPLE_SIZE = 50000
    
    def __init__(self):
        self.samples = []
        self.labels = []
    
    def add_sample(self, data: bytes, architecture: str):
        """Add a training sample."""
        self.samples.append(data)
        self.labels.append(architecture)
    
    def _extract_features(self, data: bytes) -> 'np.ndarray':
        """Extract features from one sample."""
        sample = data[:self.SAMPLE_SIZE]
        ngrams = Counter()
        
        for i in range(len(sample) - self.NGRAM_SIZE + 1):
            ngram = sample[i:i + self.NGRAM_SIZE]
            ngrams[ngram] += 1
        
        total = sum(ngrams.values())
        features = np.zeros(self.FEATURE_SIZE)
        for idx, (ngram, count) in enumerate(ngrams.most_common(self.FEATURE_SIZE)):
            features[idx] = count / total if total > 0 else 0
        
        return features
    
    def train(self, output_path: str) -> float:
        """Train model and save to disk. Returns test accuracy."""
        if not ML_AVAILABLE:
            raise RuntimeError("sklearn not available")
        
        # Extract features
        X = np.array([self._extract_features(s) for s in self.samples])
        y = np.array(self.labels)
        
        # Train/test split
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train Random Forest
        model = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        accuracy = model.score(X_test, y_test)
        
        # Save
        with open(output_path, "wb") as f:
            pickle.dump(model, f)
        
        return accuracy
