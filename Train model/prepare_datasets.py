"""
CryptoHunter Dataset Preparation

This script processes downloaded crypto libraries by:
1. Cross-compiling source code for multiple architectures
2. Running Ghidra to extract control flow graphs
3. Labeling functions based on debug symbols
4. Creating training-ready JSON datasets

Prerequisites:
- Ghidra installed (set GHIDRA_PATH environment variable)
- Cross-compilers installed (arm-linux-gnueabi-gcc, etc.)

Usage:
    python prepare_datasets.py --input ./datasets --output ./training_data
"""

import os
import sys
import json
import struct
import random
import argparse
import subprocess
from pathlib import Path
from datetime import datetime


# Ghidra configuration
GHIDRA_PATH = os.environ.get("GHIDRA_PATH", r"D:\ghidra_11.4.2_PUBLIC")
HEADLESS = os.path.join(GHIDRA_PATH, "support", "analyzeHeadless.bat")


# Crypto class mapping
CRYPTO_CLASSES = {
    0: "Non-Crypto",
    1: "AES/Block Cipher",
    2: "Hash Function",
    3: "Stream Cipher",
    4: "Public Key",
    5: "Auth/MAC",
    6: "KDF",
    7: "PRNG",
    8: "XOR Cipher",
    9: "Post-Quantum"
}

# Function name patterns for labeling
CRYPTO_PATTERNS = {
    1: ["aes", "des", "blowfish", "camellia", "cast", "block", "encrypt", "decrypt", "cipher", "cbc", "ecb", "ctr", "ofb", "cfb"],
    2: ["sha256", "sha512", "sha1", "sha3", "md5", "md4", "blake", "ripemd", "hash", "digest", "whirlpool"],
    3: ["chacha", "salsa", "rc4", "stream", "arcfour"],
    4: ["rsa", "ecdsa", "ecdh", "ed25519", "curve25519", "dh_", "dsa", "ec_", "bn_"],
    5: ["hmac", "cmac", "gmac", "poly1305", "siphash", "mac_"],
    6: ["pbkdf", "hkdf", "kdf", "scrypt", "argon", "derive"],
    7: ["drbg", "random", "prng", "entropy", "rand_"],
    8: ["xor_cipher", "otp"],
    9: ["kyber", "dilithium", "falcon", "newhope", "frodo", "saber", "ntru"]
}


def classify_function_name(func_name):
    """Classify a function by its name using pattern matching."""
    name_lower = func_name.lower()
    
    # Skip common non-crypto patterns
    skip_patterns = ["printf", "malloc", "free", "memcpy", "strlen", "strcmp", 
                     "sprintf", "fprintf", "assert", "__"]
    if any(p in name_lower for p in skip_patterns):
        return 0, "Non-Crypto", 0.95
    
    # Check for crypto patterns
    for class_id, patterns in CRYPTO_PATTERNS.items():
        for pattern in patterns:
            if pattern in name_lower:
                return class_id, CRYPTO_CLASSES[class_id], 0.85
    
    return 0, "Non-Crypto", 0.70


def extract_graphs_with_ghidra(binary_path, output_dir):
    """Extract CFGs from binary using Ghidra headless analyzer."""
    project_dir = output_dir / "ghidra_projects"
    project_dir.mkdir(exist_ok=True)
    
    script_path = Path(__file__).parent.parent / "src" / "graph_export.py"
    
    cmd = [
        HEADLESS,
        str(project_dir), "temp_proj",
        "-import", str(binary_path),
        "-postScript", str(script_path), str(output_dir),
        "-deleteProject",
        "-scriptPath", str(script_path.parent)
    ]
    
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            encoding='utf-8', errors='replace'
        )
        
        json_path = output_dir / f"{binary_path.name}.json"
        if json_path.exists():
            with open(json_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"  Ghidra error: {e}")
    
    return []


def process_binary(binary_path, output_dir, label_from_symbols=True):
    """Process a single binary file to extract labeled training data."""
    print(f"  Processing: {binary_path.name}")
    
    # Extract graphs with Ghidra
    functions = extract_graphs_with_ghidra(binary_path, output_dir)
    
    if not functions:
        return []
    
    # Label each function
    labeled_functions = []
    for func in functions:
        func_name = func.get("name", "unknown")
        
        # Classify by name
        class_id, class_name, confidence = classify_function_name(func_name)
        
        func["label"] = class_id
        func["label_name"] = class_name
        func["label_confidence"] = confidence
        func["source_binary"] = str(binary_path)
        
        labeled_functions.append(func)
    
    return labeled_functions


def generate_synthetic_samples(arch_name, count=500):
    """Generate synthetic training samples when real binaries unavailable."""
    samples = []
    
    for i in range(count):
        # Random crypto class
        class_id = random.choice(list(CRYPTO_CLASSES.keys()))
        class_name = CRYPTO_CLASSES[class_id]
        
        # Generate synthetic graph
        num_nodes = random.randint(3, 50)
        nodes = []
        edges = []
        
        for n in range(num_nodes):
            # Random opcodes (simulating P-Code operations)
            ops = random.sample(["MOV", "ADD", "SUB", "XOR", "AND", "OR", 
                                "CMP", "JMP", "CALL", "RET", "LDR", "STR"], 
                               k=random.randint(2, 8))
            
            nodes.append({
                "id": n,
                "ops": ops,
                "fk": random.randint(0, 1),  # Crypto constant flag
                "fu": random.randint(0, 1)   # Unrolled loop flag
            })
        
        # Generate edges (simple linear + some branches)
        for n in range(num_nodes - 1):
            edges.append([n, n + 1])
            if random.random() > 0.7 and n < num_nodes - 2:
                edges.append([n, random.randint(n + 1, num_nodes - 1)])
        
        sample = {
            "name": f"synthetic_{arch_name}_{class_name}_{i}",
            "arch": arch_name,
            "label": class_id,
            "label_name": class_name,
            "synthetic": True,
            "graph": {
                "nodes": nodes,
                "edges": edges
            }
        }
        samples.append(sample)
    
    return samples


def main():
    parser = argparse.ArgumentParser(description="Prepare training datasets")
    parser.add_argument("--input", "-i", default="./datasets",
                       help="Input directory with downloaded libraries")
    parser.add_argument("--output", "-o", default="./training_data",
                       help="Output directory for processed data")
    parser.add_argument("--synthetic", "-s", type=int, default=0,
                       help="Generate synthetic samples per architecture")
    
    args = parser.parse_args()
    
    input_dir = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("CryptoHunter Dataset Preparation")
    print(f"Input: {input_dir.absolute()}")
    print(f"Output: {output_dir.absolute()}")
    
    all_samples = []
    
    # Process real binaries
    if input_dir.exists():
        for lib_dir in input_dir.iterdir():
            if lib_dir.is_dir():
                print(f"\nProcessing library: {lib_dir.name}")
                
                # Find all binary files
                for root, dirs, files in os.walk(lib_dir):
                    for f in files:
                        fpath = Path(root) / f
                        if fpath.suffix in {'.o', '.so', '.a', '.elf'}:
                            samples = process_binary(fpath, output_dir)
                            all_samples.extend(samples)
    
    # Generate synthetic samples
    if args.synthetic > 0:
        print(f"\nGenerating synthetic samples...")
        architectures = ["ARM32", "ARM64", "x86", "x86-64", "MIPS-BE", "RISCV32"]
        for arch in architectures:
            samples = generate_synthetic_samples(arch, args.synthetic)
            all_samples.extend(samples)
            print(f"  {arch}: {len(samples)} samples")
    
    # Save combined dataset
    dataset_path = output_dir / "training_dataset.json"
    with open(dataset_path, "w") as f:
        json.dump(all_samples, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("Dataset Preparation Complete!")
    print("="*60)
    print(f"Total samples: {len(all_samples)}")
    
    # Class distribution
    class_counts = {}
    for s in all_samples:
        label = s.get("label", 0)
        class_counts[label] = class_counts.get(label, 0) + 1
    
    print("\nClass Distribution:")
    for class_id, count in sorted(class_counts.items()):
        print(f"  {CRYPTO_CLASSES.get(class_id, 'Unknown')}: {count}")
    
    print(f"\nDataset saved to: {dataset_path}")


if __name__ == "__main__":
    main()
