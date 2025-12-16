#!/usr/bin/env python3
"""
Train XGBoost Binary Classifier for Crypto/Non-Crypto Detection

This script trains an XGBoost model to classify functions as:
- 1 (crypto): Cryptographic functions
- 0 (non-crypto): Regular utility functions

Focus: HIGH RECALL - we must not miss any crypto functions
"""

import os
import sys
import json
import struct
import math
from pathlib import Path
from typing import List, Dict, Tuple
from datetime import datetime

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import numpy as np

try:
    import xgboost as xgb
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_auc_score
    )
except ImportError as e:
    print(f"Error: Required packages not installed: {e}")
    print("Install with: pip install xgboost scikit-learn numpy")
    sys.exit(1)


# ============================================================================
# Feature Extraction (matching src/xgboost_filter.py)
# ============================================================================

CRYPTO_CONSTANTS = {
    "aes_sbox": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
    "aes_rcon": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]),
    "sha256_h": struct.pack(">I", 0x6a09e667),
    "md5_k": struct.pack("<I", 0xd76aa478),
    "chacha_const": b"expand 32-byte k",
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


def extract_features(sample: Dict) -> List[float]:
    """
    Extract 13 features from a function sample.
    Must match src/xgboost_filter.py exactly.
    """
    features = []
    
    # Get function bytes
    raw_bytes = sample.get("bytes", "")
    if isinstance(raw_bytes, str):
        try:
            raw_bytes = bytes.fromhex(raw_bytes)
        except:
            raw_bytes = raw_bytes.encode()
    
    # Feature 1: Function size (normalized)
    size = sample.get("size", len(raw_bytes))
    features.append(min(size / 10000, 1.0))
    
    # Feature 2: Entropy (normalized)
    entropy = calculate_entropy(raw_bytes)
    features.append(entropy / 8.0)
    
    # Features 3-8: Crypto constant presence (binary flags)
    for name, const in CRYPTO_CONSTANTS.items():
        features.append(1.0 if const in raw_bytes else 0.0)
    
    # Feature 9: Number of basic blocks (normalized)
    num_blocks = sample.get("num_blocks", 1)
    features.append(min(num_blocks / 100, 1.0))
    
    # Feature 10: Number of calls (normalized)
    num_calls = sample.get("num_calls", 0)
    features.append(min(num_calls / 50, 1.0))
    
    # Feature 11: Bitwise operation ratio
    bitwise_count = sum(raw_bytes.count(op) for op in [0x83, 0xC1, 0xD1, 0x33, 0x23])
    features.append(min(bitwise_count / len(raw_bytes) if raw_bytes else 0, 1.0))
    
    # Feature 12: Loop indicator
    has_loops = sample.get("has_loops", False)
    features.append(1.0 if has_loops else 0.0)
    
    # Feature 13: Cyclomatic complexity (normalized)
    complexity = sample.get("cyclomatic_complexity", num_blocks)
    features.append(min(complexity / 50, 1.0))
    
    return features


# ============================================================================
# Training
# ============================================================================

def load_training_data(data_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """Load and prepare training data."""
    print(f"Loading data from: {data_path}")
    
    with open(data_path, 'r') as f:
        data = json.load(f)
    
    samples = data["samples"]
    print(f"Loaded {len(samples)} samples")
    
    X = []
    y = []
    
    for sample in samples:
        features = extract_features(sample)
        X.append(features)
        y.append(sample["label"])
    
    return np.array(X), np.array(y)


def train_model(X: np.ndarray, y: np.ndarray, output_path: str) -> Dict:
    """
    Train XGBoost model with focus on high recall.
    
    Returns:
        Dict with training results and metrics
    """
    print("\n" + "="*60)
    print("Training XGBoost Model")
    print("="*60)
    
    # Split data: 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    print(f"Training crypto ratio: {y_train.mean():.2%}")
    print(f"Test crypto ratio: {y_test.mean():.2%}")
    
    # Calculate class weight for imbalanced data
    scale_pos_weight = (y_train == 0).sum() / max(1, (y_train == 1).sum())
    print(f"Scale pos weight: {scale_pos_weight:.2f}")
    
    # XGBoost parameters focused on high recall
    params = {
        'n_estimators': 100,
        'max_depth': 6,
        'learning_rate': 0.1,
        'scale_pos_weight': scale_pos_weight,
        'objective': 'binary:logistic',
        'eval_metric': 'logloss',
        'use_label_encoder': False,
        'random_state': 42,
        'n_jobs': -1,
    }
    
    print("\nModel parameters:")
    for k, v in params.items():
        print(f"  {k}: {v}")
    
    # Train model
    print("\nTraining...")
    model = xgb.XGBClassifier(**params)
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=True
    )
    
    # Predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    print(f"\n{'Metric':<15} {'Score':>10}")
    print("-" * 25)
    print(f"{'Accuracy':<15} {accuracy:>10.4f}")
    print(f"{'Precision':<15} {precision:>10.4f}")
    print(f"{'RECALL':<15} {recall:>10.4f}  <- MOST IMPORTANT")
    print(f"{'F1 Score':<15} {f1:>10.4f}")
    print(f"{'AUC-ROC':<15} {auc:>10.4f}")
    
    print("\nConfusion Matrix:")
    print("              Predicted")
    print("              Non-Crypto  Crypto")
    print(f"Actual Non-Crypto    {cm[0][0]:5d}    {cm[0][1]:5d}")
    print(f"Actual Crypto        {cm[1][0]:5d}    {cm[1][1]:5d}")
    
    # False negatives are critical (missed crypto functions)
    false_negatives = cm[1][0]
    false_positives = cm[0][1]
    print(f"\nFalse Negatives (Missed Crypto): {false_negatives}")
    print(f"False Positives (False Alarms): {false_positives}")
    
    # Classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Non-Crypto", "Crypto"]))
    
    # Cross-validation
    print("\n5-Fold Cross-Validation:")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring='recall')
    print(f"  Recall scores: {cv_scores}")
    print(f"  Mean recall: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Feature importance
    print("\nFeature Importance:")
    feature_names = [
        "size", "entropy", "aes_sbox", "aes_rcon", "sha256_h", 
        "md5_k", "chacha_const", "blowfish_p", "num_blocks", 
        "num_calls", "bitwise_ratio", "has_loops", "complexity"
    ]
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for i in sorted_idx:
        print(f"  {feature_names[i]:<15}: {importances[i]:.4f}")
    
    # Save model
    model.save_model(output_path)
    print(f"\nModel saved to: {output_path}")
    
    # Also save in JSON format for portability
    json_path = output_path.replace(".json", "_model.json")
    if json_path == output_path:
        json_path = output_path.replace(".bin", ".json")
    model.save_model(json_path)
    
    # Compile results
    results = {
        "timestamp": datetime.now().isoformat(),
        "num_samples": len(X),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "auc_roc": float(auc),
        },
        "confusion_matrix": cm.tolist(),
        "cv_recall_mean": float(cv_scores.mean()),
        "cv_recall_std": float(cv_scores.std()),
        "feature_importance": {
            feature_names[i]: float(importances[i]) 
            for i in range(len(feature_names))
        },
        "model_path": output_path,
    }
    
    return results


def main():
    """Main training pipeline."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train XGBoost crypto filter")
    parser.add_argument("--data", type=str, default=None, help="Training data path")
    parser.add_argument("--output", type=str, default=None, help="Model output path")
    args = parser.parse_args()
    
    # Determine paths
    base_dir = Path(__file__).parent.parent
    
    if args.data:
        data_path = args.data
    else:
        data_path = base_dir / "models" / "xgboost_training_data.json"
    
    if args.output:
        output_path = args.output
    else:
        output_path = base_dir / "models" / "xgboost_filter.json"
    
    if not os.path.exists(data_path):
        print(f"Error: Training data not found at {data_path}")
        print("Run generate_xgboost_training_data.py first")
        sys.exit(1)
    
    # Load data
    X, y = load_training_data(str(data_path))
    
    # Train model
    results = train_model(X, y, str(output_path))
    
    # Save results
    results_path = base_dir / "models" / "xgboost_training_results.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nTraining results saved to: {results_path}")
    
    # Summary
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Recall: {results['metrics']['recall']:.2%}")
    
    if results['metrics']['recall'] >= 0.95:
        print("[OK] Target recall (95%) achieved!")
    else:
        print(f"[WARN] Recall below 95% target. Consider adjusting threshold.")
    
    print("="*60)


if __name__ == "__main__":
    main()
