#!/usr/bin/env python3
"""
Generate Training Data for XGBoost Crypto/Non-Crypto Classifier

Enhanced version with OBFUSCATION-RESISTANT training data:
- Standard crypto functions (high entropy)
- Obfuscated crypto functions (lowered entropy but retain patterns)
- Standard non-crypto functions (low entropy)
- Adversarial non-crypto (high entropy but no crypto patterns)

This forces the model to learn from ALL features, not just entropy.
"""

import os
import sys
import json
import struct
import random
import math
from typing import List, Dict, Tuple
from pathlib import Path

# ============================================================================
# Crypto Constants (for injection and detection)
# ============================================================================

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
])

AES_RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80])

SHA256_H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

CHACHA_CONST = b"expand 32-byte k"

BLOWFISH_P = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344]

# X86/ARM-like opcodes for crypto patterns
XOR_OPCODES = [0x31, 0x33, 0x35, 0x81]
ROT_OPCODES = [0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3]

# Names
CRYPTO_NAMES = [
    "aes_encrypt", "aes_decrypt", "sha256_transform", "md5_transform",
    "chacha20_block", "poly1305_update", "hmac_sha256", "gcm_ghash",
]

OBFUSCATED_NAMES = [
    "FUN_00001234", "sub_8048000", "fcn.00401000", "func_a1b2c3",
    "j_unknown", "nullsub_1", "loc_804", "_Z7func",
]

NON_CRYPTO_NAMES = [
    "main", "printf", "malloc", "free", "memcpy", "memset",
    "strcpy", "strlen", "fopen", "fclose", "socket", "connect",
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy."""
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


def inject_crypto_constant(data: bytearray, constant: bytes, pos: int = None):
    """Inject crypto constant at position."""
    if pos is None:
        pos = random.randint(0, max(0, len(data) - len(constant)))
    end = min(pos + len(constant), len(data))
    data[pos:end] = constant[:end - pos]


def add_xor_pattern(data: bytearray, density: float = 0.1):
    """Add XOR instruction patterns."""
    for i in range(len(data)):
        if random.random() < density:
            data[i] = random.choice(XOR_OPCODES)


def add_rotation_pattern(data: bytearray, density: float = 0.05):
    """Add rotation instruction patterns."""
    for i in range(len(data)):
        if random.random() < density:
            data[i] = random.choice(ROT_OPCODES)


def generate_standard_crypto() -> Dict:
    """Generate standard crypto function (high entropy, clear constants)."""
    name = random.choice(CRYPTO_NAMES)
    size = random.randint(300, 2000)
    
    # High entropy base
    data = bytearray([random.randint(0, 255) for _ in range(size)])
    
    # Inject crypto constants based on type
    if "aes" in name.lower():
        inject_crypto_constant(data, AES_SBOX)
        inject_crypto_constant(data, AES_RCON, size // 2)
    elif "sha" in name.lower():
        for i, h in enumerate(SHA256_H[:4]):
            inject_crypto_constant(data, struct.pack(">I", h), i * 20)
    elif "md5" in name.lower():
        for i, h in enumerate(MD5_INIT):
            inject_crypto_constant(data, struct.pack("<I", h), i * 16)
    elif "chacha" in name.lower():
        inject_crypto_constant(data, CHACHA_CONST)
    else:
        inject_crypto_constant(data, AES_SBOX[:8])
    
    add_xor_pattern(data, 0.08)
    add_rotation_pattern(data, 0.04)
    
    return {
        "name": name,
        "bytes": bytes(data).hex(),
        "size": size,
        "num_blocks": random.randint(15, 50),
        "num_calls": random.randint(5, 20),
        "has_loops": True,
        "cyclomatic_complexity": random.randint(15, 45),
        "label": 1,
        "type": "standard_crypto"
    }


def generate_obfuscated_crypto() -> Dict:
    """
    Generate OBFUSCATED crypto function.
    - Mangled name
    - LOWERED entropy (padding/junk)
    - BUT still has crypto constants
    - Crypto instruction patterns preserved
    """
    name = random.choice(OBFUSCATED_NAMES) + f"_{random.randint(1000, 9999)}"
    size = random.randint(500, 3000)
    
    # Start with LOWER entropy (structured padding)
    data = bytearray(size)
    for i in range(0, size, 16):
        if random.random() > 0.5:
            # Padding (reduces entropy)
            pattern = random.choice([0x00, 0x90, 0xCC, 0x55])
            for j in range(min(16, size - i)):
                data[i + j] = pattern
        else:
            for j in range(min(16, size - i)):
                data[i + j] = random.randint(0, 255)
    
    # STILL inject crypto constants (these survive obfuscation)
    crypto_type = random.choice(["aes", "sha", "md5", "chacha", "blowfish"])
    
    if crypto_type == "aes":
        inject_crypto_constant(data, AES_SBOX[:16], random.randint(100, size - 100))
        inject_crypto_constant(data, AES_RCON, random.randint(50, size - 50))
    elif crypto_type == "sha":
        for i, h in enumerate(SHA256_H[:3]):
            inject_crypto_constant(data, struct.pack(">I", h), 100 + i * 50)
    elif crypto_type == "md5":
        for i, h in enumerate(MD5_INIT[:2]):
            inject_crypto_constant(data, struct.pack("<I", h), 80 + i * 40)
    elif crypto_type == "chacha":
        inject_crypto_constant(data, CHACHA_CONST, random.randint(50, size - 50))
    else:
        inject_crypto_constant(data, struct.pack(">I", BLOWFISH_P[0]), 100)
    
    # Crypto instruction patterns (higher density)
    add_xor_pattern(data, 0.12)
    add_rotation_pattern(data, 0.06)
    
    return {
        "name": name,
        "bytes": bytes(data).hex(),
        "size": size,
        "num_blocks": random.randint(20, 80),
        "num_calls": random.randint(3, 15),
        "has_loops": True,
        "cyclomatic_complexity": random.randint(25, 60),
        "label": 1,  # Still crypto!
        "type": "obfuscated_crypto"
    }


def generate_standard_non_crypto() -> Dict:
    """Generate standard non-crypto function (low entropy)."""
    name = random.choice(NON_CRYPTO_NAMES)
    size = random.randint(50, 500)
    
    data = bytearray(size)
    patterns = [b"Hello World!", b"\x00" * 8, b"[%s] %d\n",
                bytes([0x41 + (i % 26) for i in range(16)])]
    
    pos = 0
    while pos < size:
        pattern = random.choice(patterns)
        for i, b in enumerate(pattern):
            if pos + i < size:
                data[pos + i] = b
        pos += len(pattern) + random.randint(0, 10)
    
    return {
        "name": name,
        "bytes": bytes(data).hex(),
        "size": size,
        "num_blocks": random.randint(1, 8),
        "num_calls": random.randint(0, 5),
        "has_loops": random.random() > 0.6,
        "cyclomatic_complexity": random.randint(1, 10),
        "label": 0,
        "type": "standard_non_crypto"
    }


def generate_adversarial_non_crypto() -> Dict:
    """
    Generate ADVERSARIAL non-crypto function.
    - HIGH entropy (like crypto)
    - NO crypto constants
    - Simulates: compressed data, random buffers
    """
    name = random.choice(["decompress", "inflate", "decode_buffer",
                          "random_fill", "noise_gen"] + OBFUSCATED_NAMES[:3])
    size = random.randint(200, 1500)
    
    # HIGH entropy random data
    data = bytearray([random.randint(0, 255) for _ in range(size)])
    
    # NO crypto constants, NO crypto patterns
    
    return {
        "name": name,
        "bytes": bytes(data).hex(),
        "size": size,
        "num_blocks": random.randint(1, 10),
        "num_calls": random.randint(0, 8),
        "has_loops": random.random() > 0.5,
        "cyclomatic_complexity": random.randint(2, 15),
        "label": 0,  # NOT crypto!
        "type": "adversarial_non_crypto"
    }


def generate_dataset(num_samples: int = 4000) -> List[Dict]:
    """
    Generate balanced dataset:
    - 30% Standard crypto
    - 20% Obfuscated crypto
    - 30% Standard non-crypto
    - 20% Adversarial non-crypto
    """
    n_std_crypto = int(num_samples * 0.30)
    n_obf_crypto = int(num_samples * 0.20)
    n_std_non = int(num_samples * 0.30)
    n_adv_non = num_samples - n_std_crypto - n_obf_crypto - n_std_non
    
    print(f"Generating {n_std_crypto} standard crypto samples...")
    std_crypto = [generate_standard_crypto() for _ in range(n_std_crypto)]
    
    print(f"Generating {n_obf_crypto} OBFUSCATED crypto samples...")
    obf_crypto = [generate_obfuscated_crypto() for _ in range(n_obf_crypto)]
    
    print(f"Generating {n_std_non} standard non-crypto samples...")
    std_non = [generate_standard_non_crypto() for _ in range(n_std_non)]
    
    print(f"Generating {n_adv_non} ADVERSARIAL non-crypto samples...")
    adv_non = [generate_adversarial_non_crypto() for _ in range(n_adv_non)]
    
    dataset = std_crypto + obf_crypto + std_non + adv_non
    random.shuffle(dataset)
    return dataset


def validate_dataset(dataset: List[Dict]) -> Dict:
    """Validate dataset quality."""
    stats = {
        "total": len(dataset),
        "crypto": sum(1 for d in dataset if d["label"] == 1),
        "non_crypto": sum(1 for d in dataset if d["label"] == 0),
        "by_type": {},
        "entropy_by_type": {}
    }
    
    for sample in dataset:
        t = sample.get("type", "unknown")
        stats["by_type"][t] = stats["by_type"].get(t, 0) + 1
        
        entropy = calculate_entropy(bytes.fromhex(sample["bytes"]))
        if t not in stats["entropy_by_type"]:
            stats["entropy_by_type"][t] = []
        stats["entropy_by_type"][t].append(entropy)
    
    for t, vals in stats["entropy_by_type"].items():
        stats["entropy_by_type"][t] = sum(vals) / len(vals) if vals else 0
    
    return stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate XGBoost training data (obfuscation-resistant)")
    parser.add_argument("--samples", type=int, default=4000, help="Number of samples")
    parser.add_argument("--output", type=str, default=None, help="Output path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    print("="*60)
    print("XGBoost Training Data Generator (Obfuscation-Resistant)")
    print("="*60)
    print(f"Samples: {args.samples}")
    print()
    
    dataset = generate_dataset(args.samples)
    stats = validate_dataset(dataset)
    
    print()
    print("Dataset Statistics:")
    print(f"  Total: {stats['total']}")
    print(f"  Crypto: {stats['crypto']} ({stats['crypto']/stats['total']*100:.1f}%)")
    print(f"  Non-Crypto: {stats['non_crypto']}")
    print()
    print("By Type:")
    for t, count in stats["by_type"].items():
        entropy = stats["entropy_by_type"][t]
        print(f"  {t}: {count} samples, avg entropy: {entropy:.2f}")
    
    if args.output:
        output_path = args.output
    else:
        output_path = Path(__file__).parent.parent / "models" / "xgboost_training_data.json"
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump({"metadata": stats, "samples": dataset}, f, indent=2)
    
    print()
    print(f"Dataset saved to: {output_path}")
    print("="*60)


if __name__ == "__main__":
    main()
