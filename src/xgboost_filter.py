"""
XGBoost Fast Filter
Lightweight pre-filter to identify suspicious crypto candidate functions
before running the expensive GNN inference.

Features extracted:
- Entropy of function bytes
- Presence of crypto constants (S-boxes, etc.)
- Loop depth and complexity
- Instruction mix (bitwise ops, rotations)
"""

import os
import json
import struct
import math
from typing import Dict, List, Tuple, Any
from pathlib import Path

# Try to import XGBoost
try:
    import xgboost as xgb
    import numpy as np
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠ XGBoost not available, using heuristic filter")


# Known crypto constants for detection
CRYPTO_CONSTANTS = {
    # AES S-Box (first 16 bytes)
    "aes_sbox": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
    # AES Round Constants
    "aes_rcon": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]),
    # SHA-256 Initial Values (first 8 bytes of first constant)
    "sha256_h": struct.pack(">I", 0x6a09e667),
    # MD5 Constants
    "md5_k": struct.pack("<I", 0xd76aa478),
    # ChaCha20 Constants
    "chacha_const": b"expand 32-byte k",
    # Blowfish P-array
    "blowfish_p": struct.pack(">I", 0x243f6a88),
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy


def extract_features(function_data: Dict) -> List[float]:
    """
    Extract features from a function for XGBoost classification.
    
    Args:
        function_data: Dict containing function info from Ghidra
            - bytes: raw function bytes (hex string or bytes)
            - size: function size
            - num_blocks: number of basic blocks
            - num_calls: number of call instructions
            - cyclomatic_complexity: optional complexity metric
    
    Returns:
        Feature vector [13 features]
    """
    features = []
    
    # Get function bytes
    raw_bytes = function_data.get("bytes", b"")
    if isinstance(raw_bytes, str):
        try:
            raw_bytes = bytes.fromhex(raw_bytes)
        except:
            raw_bytes = raw_bytes.encode()
    
    # Feature 1: Function size
    size = function_data.get("size", len(raw_bytes))
    features.append(min(size / 10000, 1.0))  # Normalize to 0-1
    
    # Feature 2: Entropy
    entropy = calculate_entropy(raw_bytes)
    features.append(entropy / 8.0)  # Normalize to 0-1
    
    # Feature 3-8: Crypto constant presence (binary flags)
    for name, const in CRYPTO_CONSTANTS.items():
        features.append(1.0 if const in raw_bytes else 0.0)
    
    # Feature 9: Number of basic blocks (complexity indicator)
    num_blocks = function_data.get("num_blocks", 1)
    features.append(min(num_blocks / 100, 1.0))
    
    # Feature 10: Number of calls
    num_calls = function_data.get("num_calls", 0)
    features.append(min(num_calls / 50, 1.0))
    
    # Feature 11: Bitwise operation ratio (estimated)
    bitwise_count = sum(raw_bytes.count(op) for op in [0x83, 0xC1, 0xD1, 0x33, 0x23])
    features.append(min(bitwise_count / len(raw_bytes) if raw_bytes else 0, 1.0))
    
    # Feature 12: Loop indicator (presence of backward jumps)
    has_loops = function_data.get("has_loops", False)
    features.append(1.0 if has_loops else 0.0)
    
    # Feature 13: Cyclomatic complexity
    complexity = function_data.get("cyclomatic_complexity", num_blocks)
    features.append(min(complexity / 50, 1.0))
    
    return features


class XGBoostFilter:
    """
    Fast filter using XGBoost to identify crypto candidate functions.
    """
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.threshold = 0.5  # Default suspicion threshold
        
        if XGBOOST_AVAILABLE and model_path and os.path.exists(model_path):
            try:
                self.model = xgb.Booster()
                self.model.load_model(model_path)
                print(f"✓ Loaded XGBoost filter model from {model_path}")
            except Exception as e:
                print(f"⚠ Could not load XGBoost model: {e}")
    
    def predict(self, functions: List[Dict]) -> List[Tuple[Dict, float]]:
        """
        Predict suspicion scores for a batch of functions.
        
        Args:
            functions: List of function dicts with bytes, size, etc.
            
        Returns:
            List of (function, score) tuples, sorted by score descending
        """
        if not functions:
            return []
        
        # Extract features for all functions
        feature_matrix = []
        for func in functions:
            features = extract_features(func)
            feature_matrix.append(features)
        
        if XGBOOST_AVAILABLE and self.model:
            # Use trained model
            dmatrix = xgb.DMatrix(np.array(feature_matrix))
            scores = self.model.predict(dmatrix)
        else:
            # Fallback: heuristic scoring
            scores = []
            for i, func in enumerate(functions):
                score = self._heuristic_score(func, feature_matrix[i])
                scores.append(score)
        
        # Pair functions with scores
        results = list(zip(functions, scores))
        
        # Sort by score (highest first)
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results
    
    def filter_suspicious(self, functions: List[Dict], 
                          threshold: float = None,
                          max_candidates: int = 100) -> List[Dict]:
        """
        Filter to only suspicious functions.
        
        Args:
            functions: List of function dicts
            threshold: Suspicion threshold (0-1)
            max_candidates: Maximum number to return
            
        Returns:
            List of suspicious functions with added 'suspicion_score' field
        """
        if threshold is None:
            threshold = self.threshold
        
        scored = self.predict(functions)
        
        # Filter by threshold and limit
        suspicious = []
        for func, score in scored:
            if score >= threshold and len(suspicious) < max_candidates:
                func_copy = func.copy()
                func_copy["suspicion_score"] = float(score)
                suspicious.append(func_copy)
        
        return suspicious
    
    def _heuristic_score(self, func: Dict, features: List[float]) -> float:
        """
        Fallback heuristic scoring when XGBoost is not available.
        """
        score = 0.0
        
        # High entropy is suspicious
        entropy = features[1] * 8  # Denormalize
        if entropy > 6.0:
            score += 0.3
        
        # Crypto constants are very suspicious
        const_flags = features[2:8]
        if any(f > 0 for f in const_flags):
            score += 0.5
        
        # Medium complexity functions are likely crypto
        size = features[0] * 10000  # Denormalize
        if 100 < size < 5000:
            score += 0.1
        
        # Loops are common in crypto
        if features[11] > 0:
            score += 0.15
        
        # Many bitwise ops suggest crypto
        if features[10] > 0.1:
            score += 0.2
        
        return min(score, 1.0)


def train_filter_model(training_data: List[Tuple[Dict, int]], 
                       output_path: str) -> bool:
    """
    Train an XGBoost filter model.
    
    Args:
        training_data: List of (function_dict, label) where label is 0/1
        output_path: Path to save the trained model
        
    Returns:
        True if successful
    """
    if not XGBOOST_AVAILABLE:
        print("❌ XGBoost not available for training")
        return False
    
    # Extract features and labels
    X = []
    y = []
    for func, label in training_data:
        features = extract_features(func)
        X.append(features)
        y.append(label)
    
    X = np.array(X)
    y = np.array(y)
    
    # Create DMatrix
    dtrain = xgb.DMatrix(X, label=y)
    
    # Training parameters
    params = {
        'max_depth': 4,
        'eta': 0.3,
        'objective': 'binary:logistic',
        'eval_metric': 'auc',
        'seed': 42
    }
    
    # Train
    model = xgb.train(params, dtrain, num_boost_round=50)
    
    # Save
    model.save_model(output_path)
    print(f"✓ Saved XGBoost filter model to {output_path}")
    
    return True


# Module-level instance for easy use
_filter_instance = None

def get_filter(model_path: str = None) -> XGBoostFilter:
    """Get or create the filter instance."""
    global _filter_instance
    if _filter_instance is None:
        _filter_instance = XGBoostFilter(model_path)
    return _filter_instance


def filter_functions(functions: List[Dict], 
                     threshold: float = 0.5,
                     model_path: str = None) -> List[Dict]:
    """
    Convenience function to filter suspicious functions.
    
    Args:
        functions: List of function dicts from Ghidra
        threshold: Suspicion threshold (0-1)
        model_path: Optional path to trained XGBoost model
        
    Returns:
        List of suspicious functions
    """
    flt = get_filter(model_path)
    return flt.filter_suspicious(functions, threshold)


if __name__ == "__main__":
    # Test with sample data
    test_funcs = [
        {
            "name": "aes_encrypt",
            "bytes": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]) + b"\x00" * 100,
            "size": 500,
            "num_blocks": 15,
            "has_loops": True
        },
        {
            "name": "print_hello",
            "bytes": b"Hello World" + b"\x00" * 50,
            "size": 100,
            "num_blocks": 3,
            "has_loops": False
        }
    ]
    
    flt = XGBoostFilter()
    results = flt.predict(test_funcs)
    
    print("\nXGBoost Filter Results:")
    for func, score in results:
        print(f"  {func['name']}: {score:.3f}")
