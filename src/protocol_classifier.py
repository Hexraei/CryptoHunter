"""
Protocol Classifier Module
Multi-stage protocol detection using XGBoost + heuristic ensemble.

Following HEURISTICS_AND_IMPROVEMENTS.md approach:
Stage 1: Fast heuristic pre-filtering
Stage 2: Feature extraction (147 features)
Stage 3: XGBoost ensemble prediction
Stage 4: Confidence thresholding
"""

import os
import math
import struct
import pickle
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter

# Model path
MODELS_DIR = Path(__file__).parent.parent / "models"
PROTOCOL_MODEL_PATH = MODELS_DIR / "protocol_classifier.pkl"


# =============================================================================
# Feature Extraction
# =============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    frequencies = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in frequencies.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    
    return entropy


def extract_block_entropies(data: bytes, block_size: int = 256, num_blocks: int = 16) -> List[float]:
    """Extract entropy for multiple blocks."""
    entropies = []
    for i in range(min(num_blocks, len(data) // block_size)):
        block = data[i * block_size:(i + 1) * block_size]
        entropies.append(calculate_entropy(block))
    
    # Pad with zeros if needed
    while len(entropies) < num_blocks:
        entropies.append(0.0)
    
    return entropies


def extract_byte_frequencies(data: bytes, num_buckets: int = 32) -> List[float]:
    """Extract normalized byte frequency distribution."""
    if not data:
        return [0.0] * num_buckets
    
    # Bucket bytes into groups
    frequencies = [0] * num_buckets
    bucket_size = 256 // num_buckets
    
    for byte in data:
        bucket = min(byte // bucket_size, num_buckets - 1)
        frequencies[bucket] += 1
    
    # Normalize
    total = len(data)
    return [f / total for f in frequencies]


def extract_ngram_features(data: bytes, n: int = 2, top_k: int = 16) -> List[float]:
    """Extract n-gram frequency features."""
    if len(data) < n:
        return [0.0] * top_k
    
    ngrams = Counter()
    for i in range(len(data) - n + 1):
        ngram = tuple(data[i:i+n])
        ngrams[ngram] += 1
    
    # Get top-k frequencies (normalized)
    total = sum(ngrams.values())
    top_ngrams = [count / total for _, count in ngrams.most_common(top_k)]
    
    # Pad if needed
    while len(top_ngrams) < top_k:
        top_ngrams.append(0.0)
    
    return top_ngrams


def detect_magic_bytes(data: bytes) -> Dict[str, bool]:
    """Detect known magic byte patterns."""
    if len(data) < 4:
        return {}
    
    header = data[:16]
    
    patterns = {
        "elf": header[:4] == b'\x7fELF',
        "pe": header[:2] == b'MZ',
        "gzip": header[:2] == b'\x1f\x8b',
        "zip": header[:4] == b'PK\x03\x04',
        "lzma": header[:3] == b'\x5d\x00\x00',
        "tls_record": header[0] in range(0x14, 0x18) and header[1:3] == b'\x03\x01',
        "tls_handshake": header[0] == 0x16 and header[1:3] in (b'\x03\x01', b'\x03\x03'),
        "ssh": b'SSH-' in data[:32],
        "http": data[:4] in (b'HTTP', b'GET ', b'POST', b'HEAD'),
        "dns": len(data) > 12 and data[2:4] in (b'\x01\x00', b'\x81\x80'),
        "modbus": len(data) >= 7 and data[7] in range(1, 128),  # Modbus function codes
        "dnp3": header[:2] == b'\x05\x64',
        "mqtt": header[0] in range(0x10, 0xF0, 0x10),  # MQTT control packet types
        "coap": (header[0] >> 6) == 1,  # CoAP version 1
    }
    
    return patterns


def extract_structural_features(data: bytes) -> List[float]:
    """Extract structural features like TLV patterns, alignment."""
    features = []
    
    # Printable ratio
    printable = sum(1 for b in data if 32 <= b <= 126)
    features.append(printable / len(data) if data else 0)
    
    # Null byte ratio
    null_bytes = sum(1 for b in data if b == 0)
    features.append(null_bytes / len(data) if data else 0)
    
    # High byte ratio (>127)
    high_bytes = sum(1 for b in data if b > 127)
    features.append(high_bytes / len(data) if data else 0)
    
    # Word alignment score
    if len(data) >= 4:
        aligned = sum(1 for i in range(0, len(data) - 3, 4) 
                     if struct.unpack('<I', data[i:i+4])[0] % 4 == 0)
        features.append(aligned / (len(data) // 4))
    else:
        features.append(0.0)
    
    # Length field detection (common in protocols)
    length_matches = 0
    for i in range(min(100, len(data) - 2)):
        potential_len = struct.unpack('<H', data[i:i+2])[0] if i + 2 <= len(data) else 0
        if 4 <= potential_len <= len(data) - i:
            length_matches += 1
    features.append(min(1.0, length_matches / 20))
    
    return features


def extract_all_features(data: bytes) -> List[float]:
    """
    Extract all 147 features for XGBoost classification.
    """
    features = []
    
    # Limit data size for performance
    sample = data[:8192] if len(data) > 8192 else data
    
    # 1. Block entropies (16 features)
    features.extend(extract_block_entropies(sample))
    
    # 2. Byte frequency distribution (32 features)
    features.extend(extract_byte_frequencies(sample))
    
    # 3. Bigram features (16 features)
    features.extend(extract_ngram_features(sample, n=2, top_k=16))
    
    # 4. Trigram features (16 features)
    features.extend(extract_ngram_features(sample, n=3, top_k=16))
    
    # 5. Magic byte detection (14 features)
    magic = detect_magic_bytes(sample)
    for key in ["elf", "pe", "gzip", "zip", "lzma", "tls_record", "tls_handshake",
                "ssh", "http", "dns", "modbus", "dnp3", "mqtt", "coap"]:
        features.append(1.0 if magic.get(key, False) else 0.0)
    
    # 6. Structural features (5 features)
    features.extend(extract_structural_features(sample))
    
    # 7. Global statistics (48 features)
    features.append(calculate_entropy(sample))  # Global entropy
    features.append(len(data))  # File size
    features.append(min(1.0, len(data) / 1000000))  # Normalized size
    
    # Byte value statistics
    byte_array = list(sample)
    if byte_array:
        features.append(sum(byte_array) / len(byte_array) / 255)  # Mean
        features.append(max(byte_array) / 255)  # Max
        features.append(min(byte_array) / 255)  # Min
        variance = sum((b - sum(byte_array)/len(byte_array))**2 for b in byte_array) / len(byte_array)
        features.append(variance / 65536)  # Variance normalized
    else:
        features.extend([0.0, 0.0, 0.0, 0.0])
    
    # Pad to exactly 147 features
    while len(features) < 147:
        features.append(0.0)
    
    return features[:147]


# =============================================================================
# Protocol Classes
# =============================================================================

PROTOCOL_CLASSES = {
    0: "unknown",
    1: "tls_1.2",
    2: "tls_1.3", 
    3: "ssh",
    4: "ipsec",
    5: "http",
    6: "https",
    7: "dns",
    8: "dhcp",
    9: "ntp",
    10: "smtp",
    11: "ftp",
    12: "modbus",
    13: "dnp3",
    14: "bacnet",
    15: "mqtt",
    16: "coap",
    17: "zigbee",
    18: "zwave",
    19: "bluetooth",
    20: "ble",
    21: "wifi",
    22: "lora",
    23: "canbus",
    24: "profinet",
    25: "ethernet_ip",
    26: "opc_ua",
    27: "s7comm",
    28: "iec61850",
    29: "firmware_generic",
}


# =============================================================================
# Protocol Classifier
# =============================================================================

class ProtocolClassifier:
    """
    Multi-stage protocol classifier using XGBoost + heuristic ensemble.
    """
    
    def __init__(self):
        self.model = None
        self.model_loaded = False
        self.confidence_threshold = 0.7
        
        # Try to load XGBoost model
        self._load_model()
    
    def _load_model(self):
        """Load the XGBoost model from disk."""
        try:
            if PROTOCOL_MODEL_PATH.exists():
                with open(PROTOCOL_MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                self.model_loaded = True
                print(f"  Loaded protocol classifier: {PROTOCOL_MODEL_PATH.name}")
        except Exception as e:
            print(f"  Could not load protocol classifier: {e}")
            self.model_loaded = False
    
    def heuristic_detect(self, data: bytes, classifications: List[Dict] = None) -> List[Dict]:
        """
        Stage 1: Fast heuristic pre-filter based on magic bytes and crypto combinations.
        """
        protocols = []
        magic = detect_magic_bytes(data)
        
        # TLS Detection
        if magic.get("tls_handshake") or magic.get("tls_record"):
            protocols.append({
                "name": "TLS",
                "description": "TLS/SSL Protocol detected via magic bytes",
                "confidence": 0.90,
                "method": "heuristic_magic",
                "components": ["TLS Record", "Handshake"]
            })
        
        # SSH Detection
        if magic.get("ssh"):
            protocols.append({
                "name": "SSH",
                "description": "SSH Protocol detected",
                "confidence": 0.95,
                "method": "heuristic_magic",
                "components": ["SSH Banner"]
            })
        
        # HTTP Detection
        if magic.get("http"):
            protocols.append({
                "name": "HTTP",
                "description": "HTTP Protocol detected",
                "confidence": 0.90,
                "method": "heuristic_magic",
                "components": ["HTTP Request/Response"]
            })
        
        # Industrial protocols
        if magic.get("modbus"):
            protocols.append({
                "name": "Modbus",
                "description": "Modbus industrial protocol",
                "confidence": 0.80,
                "method": "heuristic_magic",
                "components": ["Modbus Frame"]
            })
        
        if magic.get("dnp3"):
            protocols.append({
                "name": "DNP3",
                "description": "DNP3 SCADA protocol",
                "confidence": 0.85,
                "method": "heuristic_magic",
                "components": ["DNP3 Frame"]
            })
        
        # Crypto-based protocol detection (from GNN classifications)
        if classifications:
            class_ids = {c.get("class_id", 0) for c in classifications}
            
            # TLS: AES + Hash + Public Key
            if 1 in class_ids and 2 in class_ids and not any(p["name"] == "TLS" for p in protocols):
                protocols.append({
                    "name": "TLS_HANDSHAKE",
                    "description": "TLS/SSL detected via crypto combination",
                    "confidence": 0.85 if 4 in class_ids else 0.70,
                    "method": "heuristic_crypto",
                    "components": ["AES", "SHA", "RSA" if 4 in class_ids else None]
                })
            
            # SSH: Block cipher + Public Key
            if 1 in class_ids and 4 in class_ids:
                if not any(p["name"] == "SSH" for p in protocols):
                    protocols.append({
                        "name": "SSH_KEX",
                        "description": "SSH Key Exchange",
                        "confidence": 0.75,
                        "method": "heuristic_crypto",
                        "components": ["Encryption", "PublicKey"]
                    })
            
            # Secure Boot
            if 2 in class_ids and 4 in class_ids:
                protocols.append({
                    "name": "SECURE_BOOT",
                    "description": "Secure Boot Chain",
                    "confidence": 0.70,
                    "method": "heuristic_crypto",
                    "components": ["Hash", "Signature"]
                })
        
        return protocols
    
    def xgboost_predict(self, data: bytes) -> List[Dict]:
        """
        Stage 3: XGBoost classification with probability scores.
        """
        if not self.model_loaded or self.model is None:
            return []
        
        try:
            # Extract features
            features = extract_all_features(data)
            
            # Reshape for prediction
            import numpy as np
            X = np.array(features).reshape(1, -1)
            
            # Get prediction and probabilities
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Get top predictions above threshold
            results = []
            top_indices = np.argsort(probabilities)[::-1][:3]  # Top 3
            
            for idx in top_indices:
                prob = probabilities[idx]
                if prob >= 0.1:  # Only include significant predictions
                    protocol_name = PROTOCOL_CLASSES.get(idx, f"protocol_{idx}")
                    results.append({
                        "name": protocol_name.upper(),
                        "description": f"Detected via XGBoost classifier",
                        "confidence": float(prob),
                        "method": "xgboost",
                        "class_id": int(idx),
                        "components": []
                    })
            
            return results
            
        except Exception as e:
            print(f"  XGBoost prediction failed: {e}")
            return []
    
    def fuse_results(self, heuristic_results: List[Dict], xgboost_results: List[Dict]) -> List[Dict]:
        """
        Stage 4: Confidence thresholding and result fusion.
        
        Strategy:
        1. If XGBoost confidence > 0.7, prefer XGBoost
        2. If heuristic matches XGBoost, boost confidence
        3. Include both if different protocols detected
        """
        fused = []
        seen_protocols = set()
        
        # First pass: High-confidence XGBoost results
        for xgb in xgboost_results:
            if xgb["confidence"] >= self.confidence_threshold:
                name = xgb["name"]
                
                # Check if heuristic agrees
                heuristic_match = next((h for h in heuristic_results 
                                       if h["name"].upper() in name.upper() or 
                                       name.upper() in h["name"].upper()), None)
                
                if heuristic_match:
                    # Boost confidence when both agree
                    xgb["confidence"] = min(0.99, (xgb["confidence"] + heuristic_match["confidence"]) / 2 + 0.1)
                    xgb["method"] = "ensemble"
                    xgb["components"] = heuristic_match.get("components", [])
                
                fused.append(xgb)
                seen_protocols.add(name)
        
        # Second pass: Add heuristic results not covered by XGBoost
        for heur in heuristic_results:
            name = heur["name"]
            if not any(name.upper() in seen or seen in name.upper() for seen in seen_protocols):
                heur["method"] = "heuristic"
                fused.append(heur)
                seen_protocols.add(name)
        
        # Third pass: Low-confidence XGBoost as suggestions
        for xgb in xgboost_results:
            name = xgb["name"]
            if xgb["confidence"] < self.confidence_threshold and name not in seen_protocols:
                xgb["description"] = f"Possible {name} (low confidence)"
                fused.append(xgb)
        
        # Sort by confidence
        fused.sort(key=lambda x: x["confidence"], reverse=True)
        
        return fused
    
    def detect(self, data: bytes, classifications: List[Dict] = None) -> List[Dict]:
        """
        Main detection method - runs full multi-stage pipeline.
        
        Args:
            data: Raw binary data
            classifications: Optional GNN crypto classifications for context
            
        Returns:
            List of detected protocols with confidence scores
        """
        # Stage 1: Heuristic pre-filter
        heuristic_results = self.heuristic_detect(data, classifications)
        
        # Stage 2-3: XGBoost classification
        xgboost_results = self.xgboost_predict(data)
        
        # Stage 4: Fusion
        return self.fuse_results(heuristic_results, xgboost_results)


# =============================================================================
# Convenience Functions
# =============================================================================

# Global instance for reuse
_classifier_instance = None

def get_classifier() -> ProtocolClassifier:
    """Get or create a singleton classifier instance."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = ProtocolClassifier()
    return _classifier_instance


def detect_protocols_xgboost(data: bytes, classifications: List[Dict] = None) -> List[Dict]:
    """
    Detect protocols using XGBoost + heuristic ensemble.
    
    This is the main entry point for protocol detection.
    """
    classifier = get_classifier()
    return classifier.detect(data, classifications)


# =============================================================================
# CLI Testing
# =============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python protocol_classifier.py <binary_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    classifier = ProtocolClassifier()
    results = classifier.detect(data)
    
    print(f"\nProtocol Detection Results for {sys.argv[1]}:")
    print("=" * 60)
    
    if results:
        for r in results:
            print(f"  {r['name']:20s} {r['confidence']*100:5.1f}%  [{r['method']}]")
            if r.get('components'):
                print(f"    Components: {', '.join(str(c) for c in r['components'] if c)}")
    else:
        print("  No protocols detected")
