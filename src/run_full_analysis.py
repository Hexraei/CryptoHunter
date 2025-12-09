# run_full_analysis.py - Complete CryptoHunter Analysis Pipeline
# Orchestrates: Binwalk → Ghidra → Fast Filter → GNN → Protocol Detection → Angr Verification
#
# Usage: python run_full_analysis.py <binary_file> [--output output.json]
#        python run_full_analysis.py firmware.bin --firmware  # Extract first

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime


# =============================================================================
# Configuration
# =============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GHIDRA_PATH = os.environ.get("GHIDRA_PATH", r"D:\ghidra_11.4.2_PUBLIC")
HEADLESS = os.path.join(GHIDRA_PATH, "support", "analyzeHeadless.bat")
GRAPH_EXPORT_SCRIPT = os.path.join(BASE_DIR, "graph_export.py")
MODEL_PATH = os.path.join(BASE_DIR, "sota_crypto_model.pt")
TEMP_DIR = os.path.join(BASE_DIR, "temp_analysis")

# Binwalk settings
BINWALK_CMD = "binwalk"

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


# =============================================================================
# Step 0: Firmware Extraction (Binwalk)
# =============================================================================

def check_binwalk_available():
    """Check if binwalk is installed."""
    try:
        result = subprocess.run([BINWALK_CMD, '--help'], capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def is_firmware_image(filepath):
    """
    Detect if file is a firmware image that needs extraction.
    
    Returns True if file appears to be a firmware image (not a raw binary).
    """
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(16)
        
        # Check for common firmware container signatures
        firmware_signatures = [
            b'\x27\x05\x19\x56',  # uImage header
            b'UBI#',              # UBI filesystem
            b'hsqs',              # SquashFS (little-endian)
            b'sqsh',              # SquashFS (big-endian)
            b'\x1f\x8b',          # gzip compressed
            b'BZh',               # bzip2 compressed
            b'\xfd7zXZ',          # xz compressed
            b'PK\x03\x04',        # ZIP archive
        ]
        
        for sig in firmware_signatures:
            if magic.startswith(sig):
                return True
        
        # Check if file has multiple binwalk signatures (indicates container)
        result = subprocess.run(
            [BINWALK_CMD, '-B', filepath],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        lines = [l for l in result.stdout.split('\n') if l.strip() and not l.startswith('DECIMAL')]
        return len(lines) > 3  # Multiple signatures = likely firmware
        
    except:
        return False


def extract_firmware_with_binwalk(firmware_path, output_dir):
    """
    Extract firmware using binwalk (primary), unblob (backup), or Python carving (fallback).
    
    Args:
        firmware_path: Path to firmware file
        output_dir: Directory to extract to
        
    Returns:
        List of extracted binary files
    """
    print(f"\n{'='*60}")
    print("STEP 0: Firmware Extraction (Binwalk + Unblob + Python)")
    print(f"{'='*60}")
    print(f"  Firmware: {os.path.basename(firmware_path)}")
    
    binwalk_available = check_binwalk_available()
    unblob_available = check_unblob_available()
    
    print(f"  Tools: binwalk={binwalk_available}, unblob={unblob_available}")
    
    os.makedirs(output_dir, exist_ok=True)
    binaries = []
    
    # Try binwalk first
    if binwalk_available:
        binaries = _try_binwalk_extraction(firmware_path, output_dir)
    
    # Fallback to unblob if binwalk failed or found nothing
    if not binaries and unblob_available:
        print("  → Trying unblob as backup...")
        unblob_dir = output_dir + "_unblob"
        binaries = _try_unblob_extraction(firmware_path, unblob_dir)
    
    # PYTHON FALLBACK: Pure Python extraction when no CLI tools available
    if not binaries:
        print("  → Trying Python-based extraction...")
        binaries = _try_python_extraction(firmware_path, output_dir)
    
    if binaries:
        print(f"   Extracted {len(binaries)} binaries from firmware")
        for b in binaries[:5]:
            print(f"    • {os.path.basename(b)}")
        if len(binaries) > 5:
            print(f"    ... and {len(binaries) - 5} more")
        return binaries
    
    print("   No binaries extracted, using original file")
    return [firmware_path]


def _try_python_extraction(firmware_path, output_dir):
    """Pure Python firmware extraction - carves embedded content."""
    import lzma
    import gzip
    import struct
    
    binaries = []
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        with open(firmware_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        print(f"    Scanning {file_size} bytes for embedded content...")
        
        # 1. Look for embedded ELF files
        elf_magic = b'\x7fELF'
        offset = 0
        elf_count = 0
        while offset < len(data) - 4:
            idx = data.find(elf_magic, offset)
            if idx == -1:
                break
            
            # Try to determine ELF size from header
            try:
                e_shoff = struct.unpack('<I', data[idx+32:idx+36])[0]  # Section header offset
                e_shentsize = struct.unpack('<H', data[idx+46:idx+48])[0]  # Section entry size
                e_shnum = struct.unpack('<H', data[idx+48:idx+50])[0]  # Number of sections
                elf_size = e_shoff + (e_shentsize * e_shnum)
                if elf_size < 100 or elf_size > 10000000:  # Sanity check
                    elf_size = min(500000, len(data) - idx)
            except:
                elf_size = min(500000, len(data) - idx)
            
            elf_data = data[idx:idx+elf_size]
            out_path = os.path.join(output_dir, f"embedded_elf_{elf_count}.elf")
            with open(out_path, 'wb') as f:
                f.write(elf_data)
            binaries.append(out_path)
            elf_count += 1
            offset = idx + elf_size
            if elf_count >= 10:
                break
        
        if elf_count > 0:
            print(f"    Found {elf_count} embedded ELF files")
        
        # 2. Look for LZMA streams
        lzma_magic = b'\x5d\x00\x00'
        lzma_offset = data.find(lzma_magic)
        if lzma_offset > 0:
            try:
                lzma_data = lzma.decompress(data[lzma_offset:])
                out_path = os.path.join(output_dir, "lzma_decompressed.bin")
                with open(out_path, 'wb') as f:
                    f.write(lzma_data)
                binaries.append(out_path)
                print(f"    Decompressed LZMA stream: {len(lzma_data)} bytes")
            except:
                pass
        
        # 3. Look for gzip streams
        gzip_magic = b'\x1f\x8b'
        gzip_offset = data.find(gzip_magic)
        if gzip_offset > 0:
            try:
                import io
                gz_data = gzip.GzipFile(fileobj=io.BytesIO(data[gzip_offset:])).read()
                out_path = os.path.join(output_dir, "gzip_decompressed.bin")
                with open(out_path, 'wb') as f:
                    f.write(gz_data)
                binaries.append(out_path)
                print(f"    Decompressed gzip stream: {len(gz_data)} bytes")
            except:
                pass
        
        # 4. Look for SquashFS
        sqsh_offset = data.find(b'sqsh')
        hsqs_offset = data.find(b'hsqs')
        if sqsh_offset > 0 or hsqs_offset > 0:
            off = sqsh_offset if sqsh_offset > 0 else hsqs_offset
            # Can't decompress SquashFS without external tools, but flag it
            print(f"    Found SquashFS at offset {off} (requires external tools)")
        
        # 5. If still nothing, just return the original as analyzable
        if not binaries:
            print("    No embedded content found, using original file")
        
    except Exception as e:
        print(f"    Python extraction error: {e}")
    
    return binaries


def check_unblob_available():
    """Check if unblob is installed (backup extractor)."""
    try:
        result = subprocess.run(['unblob', '--help'], capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _try_binwalk_extraction(firmware_path, output_dir):
    """Try extraction with binwalk, return list of binaries."""
    cmd = [
        BINWALK_CMD, '-e', '-M',
        '-d', '5',
        '-C', output_dir,
        firmware_path
    ]
    
    try:
        subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=300, encoding='utf-8', errors='replace'
        )
        return _find_binaries_in_dir(output_dir)
    except:
        return []


def _try_unblob_extraction(firmware_path, output_dir):
    """Try extraction with unblob, return list of binaries."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = ['unblob', '--extract-dir', output_dir, '--depth', '5', firmware_path]
    
    try:
        subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=300, encoding='utf-8', errors='replace'
        )
        return _find_binaries_in_dir(output_dir)
    except:
        return []


def _find_binaries_in_dir(directory):
    """Find ELF/binary files in extracted directory."""
    from pathlib import Path
    binaries = []
    binary_extensions = {'.so', '.o', '.elf', '.bin', '.ko', '.a', '.out'}
    
    for root, dirs, files in os.walk(directory):
        for f in files:
            full_path = os.path.join(root, f)
            ext = Path(f).suffix.lower()
            
            if ext in binary_extensions:
                binaries.append(full_path)
                continue
            
            try:
                with open(full_path, 'rb') as bf:
                    if bf.read(4) == b'\x7fELF':
                        binaries.append(full_path)
            except:
                pass
    
    return binaries


# =============================================================================
# Step 1: Ghidra Graph Extraction
# =============================================================================


def extract_graph_with_ghidra(binary_path, output_dir, architecture=None):
    """
    Extract control flow graph using Ghidra headless analyzer.
    
    Input: 
        binary_path: Path to binary file
        output_dir: Directory for output
        architecture: Detected architecture (e.g., "ARM64", "ARM32", "MIPS-BE")
    Output: JSON file with function graphs
    """
    print(f"\n{'='*60}")
    print("STEP 1: Ghidra Graph Extraction")
    print(f"{'='*60}")
    print(f"  Binary: {os.path.basename(binary_path)}")
    
    os.makedirs(output_dir, exist_ok=True)
    project_dir = os.path.join(output_dir, "ghidra_proj")
    os.makedirs(project_dir, exist_ok=True)
    
    # Map our architecture names to Ghidra processor names
    GHIDRA_PROCESSOR_MAP = {
        # ARM variants
        "ARM32": "ARM:LE:32:v7",
        "ARM-Thumb": "ARM:LE:32:v7",
        "ARM32/BE": "ARM:BE:32:v7",
        "ARM64": "AARCH64:LE:64:v8A",
        "ARM64/64-bit": "AARCH64:LE:64:v8A",
        "ARM/Cortex-M": "ARM:LE:32:Cortex",
        
        # x86 variants
        "x86": "x86:LE:32:default",
        "x86-64": "x86:LE:64:default",
        "x86-64/64-bit": "x86:LE:64:default",
        
        # MIPS variants
        "MIPS-BE": "MIPS:BE:32:default",
        "MIPS-BE/BE": "MIPS:BE:32:default",
        "MIPS-LE": "MIPS:LE:32:default",
        "MIPS64": "MIPS:BE:64:default",
        
        # Other
        "RISCV32": "RISCV:LE:32:RV32IC",
        "RISC-V": "RISCV:LE:32:RV32IC",
        "RISC-V/ESP32-C3": "RISCV:LE:32:RV32IC",
        "RISC-V/ESP32-C6": "RISCV:LE:32:RV32IC",
        "PowerPC": "PowerPC:BE:32:default",
        "Xtensa": "Xtensa:LE:32:default",
        "Xtensa/ESP32": "Xtensa:LE:32:default",
        "Xtensa/ESP32-LX6": "Xtensa:LE:32:default",
        "Xtensa/ESP32-S2-LX7": "Xtensa:LE:32:default",
        "Xtensa/ESP32-S3-LX7": "Xtensa:LE:32:default",
        
        # Heuristic-detected architectures
        "AVR": "avr8:LE:16:atmega256",
        "AVR/Intel-HEX": "avr8:LE:16:atmega256",
        "Z80": "z80:LE:16:default",
        "Z80/S-Record": "z80:LE:16:default",
    }
    
    cmd = [
        HEADLESS,
        project_dir, "temp_proj",
        "-import", binary_path,
        "-postScript", GRAPH_EXPORT_SCRIPT, output_dir,
        "-deleteProject",
        "-scriptPath", BASE_DIR
    ]
    
    # Add processor specification if we detected the architecture
    if architecture:
        # Clean up architecture string
        arch_clean = architecture.split('/')[0] if '/' in architecture else architecture
        ghidra_proc = GHIDRA_PROCESSOR_MAP.get(architecture) or GHIDRA_PROCESSOR_MAP.get(arch_clean)
        
        if ghidra_proc:
            cmd.extend(["-processor", ghidra_proc])
            print(f"  Architecture: {architecture} -> Ghidra: {ghidra_proc}")
        else:
            print(f"  Architecture: {architecture} (letting Ghidra auto-detect)")
    else:
        print(f"  Architecture: Auto-detect (no hint provided)")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            encoding='utf-8',
            errors='replace'
        )
        
        # Find output JSON
        binary_name = os.path.basename(binary_path)
        json_path = os.path.join(output_dir, f"{binary_name}.json")
        
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                functions = json.load(f)
            print(f"   Extracted {len(functions)} functions")
            return functions
        else:
            print(f"   No graph output generated")
            return []
            
    except subprocess.TimeoutExpired:
        print("   Ghidra analysis timed out")
        return []
    except Exception as e:
        print(f"   Ghidra error: {e}")
        return []


# =============================================================================
# Step 2: Fast Filter (XGBoost Pre-filter)
# =============================================================================

def fast_filter_functions(functions):
    """
    Quick filter to identify suspicious crypto regions using XGBoost.
    
    Input: List of function graphs
    Output: Filtered list of suspicious functions
    """
    print(f"\n{'='*60}")
    print("STEP 2: Fast Filter (XGBoost Pre-Filter)")
    print(f"{'='*60}")
    print(f"  Input: {len(functions)} functions")
    
    if not functions:
        return []
    
    # Try to use trained XGBoost model
    model_path = os.path.join(BASE_DIR, "..", "models", "xgboost_filter.json")
    
    try:
        from xgboost_filter import XGBoostFilter
        
        if os.path.exists(model_path):
            xgb_filter = XGBoostFilter(model_path)
            print(f"  Using trained XGBoost model")
            
            # Prepare function data for XGBoost
            prepared_funcs = []
            for func in functions:
                graph = func.get("graph", {})
                nodes = graph.get("nodes", [])
                
                # Extract bytes if available, otherwise use placeholder
                func_bytes = func.get("bytes", b"")
                if isinstance(func_bytes, str):
                    try:
                        func_bytes = bytes.fromhex(func_bytes)
                    except:
                        func_bytes = b"\x00" * 100
                
                prepared = {
                    "name": func.get("name", ""),
                    "bytes": func_bytes.hex() if isinstance(func_bytes, bytes) else func_bytes,
                    "size": func.get("size", len(func_bytes) if func_bytes else 100),
                    "num_blocks": len(nodes) if nodes else func.get("num_blocks", 5),
                    "num_calls": func.get("num_calls", 0),
                    "has_loops": func.get("has_loops", True),
                    "cyclomatic_complexity": func.get("cyclomatic_complexity", len(nodes)),
                    "_original": func  # Keep original for later
                }
                prepared_funcs.append(prepared)
            
            # Filter using XGBoost (use lower threshold for high recall)
            suspicious_prepared = xgb_filter.filter_suspicious(
                prepared_funcs, 
                threshold=0.3,  # Lower threshold to catch more crypto
                max_candidates=200
            )
            
            # Map back to original functions
            suspicious = []
            for p in suspicious_prepared:
                orig = p.get("_original", p)
                orig["suspicion_score"] = p.get("suspicion_score", 0.5)
                suspicious.append(orig)
            
            print(f"   XGBoost filtered to {len(suspicious)} suspicious functions")
            print(f"  -> Reduced by {100*(1 - len(suspicious)/max(1,len(functions))):.1f}%")
            return suspicious
            
    except ImportError:
        print("  XGBoost module not available, using heuristics")
    except Exception as e:
        print(f"  XGBoost error: {e}, using heuristics")
    
    # Fallback: Heuristic-based filtering
    print("  Using heuristic filtering (XGBoost model not loaded)")
    
    crypto_keywords = [
        "aes", "sha", "md5", "encrypt", "decrypt", "cipher", "hash",
        "key", "block", "round", "sbox", "mix", "xor", "chacha", "poly",
        "hmac", "pbkdf", "drbg", "random", "rsa", "ecc", "ecdsa", "sign",
        "verify", "kyber", "dilithium", "curve", "dh", "mac", "gcm"
    ]
    
    skip_patterns = ["printf", "malloc", "free", "memcpy", "strlen", "main", "__"]
    
    suspicious = []
    
    for func in functions:
        name = func.get("name", "").lower()
        score = 0.0
        
        # Check for crypto keywords
        for keyword in crypto_keywords:
            if keyword in name:
                score += 0.4
                break
        
        # Check for skip patterns
        for pattern in skip_patterns:
            if pattern in name:
                score -= 0.6
        
        # Check operation density
        graph = func.get("graph", {})
        nodes = graph.get("nodes", [])
        
        xor_count = sum(
            1 for n in nodes for op in n.get("ops", []) 
            if "XOR" in op.upper()
        )
        
        shift_count = sum(
            1 for n in nodes for op in n.get("ops", [])
            if any(s in op.upper() for s in ["LSL", "LSR", "ROL", "ROR"])
        )
        
        if xor_count >= 3:
            score += 0.2
        if shift_count >= 3:
            score += 0.2
        
        # Check for crypto constants
        const_count = sum(1 for n in nodes if n.get("fk", 0) > 0)
        if const_count >= 1:
            score += 0.3
        
        func["suspicion_score"] = min(1.0, max(0.0, score))
        
        if func["suspicion_score"] >= 0.3:
            suspicious.append(func)
    
    suspicious.sort(key=lambda x: x["suspicion_score"], reverse=True)
    
    print(f"   Heuristic filtered to {len(suspicious)} suspicious functions")
    print(f"  -> Reduced by {100*(1 - len(suspicious)/max(1,len(functions))):.1f}%")
    
    return suspicious


# =============================================================================
# Step 3: GNN Classification
# =============================================================================

def classify_with_gnn(functions):
    """
    Classify functions using trained GNN model.
    
    Input: Filtered list of suspicious functions
    Output: Functions with class predictions and confidence scores
    """
    print(f"\n{'='*60}")
    print("STEP 3: GNN Deep Learning Classification")
    print(f"{'='*60}")
    
    try:
        import torch
        import torch.nn.functional as F
        from torch_geometric.data import Data
        from torch_geometric.nn import GINConv, global_add_pool
        
        device = torch.device('cpu')
        HIDDEN_DIM = 128
        NUM_CLASSES = 10
        
        # Define model architecture
        class SOTA_GIN(torch.nn.Module):
            def __init__(self):
                super(SOTA_GIN, self).__init__()
                
                def make_mlp(in_dim, out_dim):
                    return torch.nn.Sequential(
                        torch.nn.Linear(in_dim, out_dim),
                        torch.nn.BatchNorm1d(out_dim),
                        torch.nn.ReLU(),
                        torch.nn.Linear(out_dim, out_dim)
                    )
                
                self.conv1 = GINConv(make_mlp(20, HIDDEN_DIM))
                self.conv2 = GINConv(make_mlp(HIDDEN_DIM, HIDDEN_DIM))
                self.conv3 = GINConv(make_mlp(HIDDEN_DIM, HIDDEN_DIM))
                self.conv4 = GINConv(make_mlp(HIDDEN_DIM, HIDDEN_DIM))
                self.lin1 = torch.nn.Linear(HIDDEN_DIM, HIDDEN_DIM)
                self.lin2 = torch.nn.Linear(HIDDEN_DIM, NUM_CLASSES)
            
            def forward(self, x, edge_index, batch):
                x = F.relu(self.conv1(x, edge_index))
                x = F.relu(self.conv2(x, edge_index))
                x = F.relu(self.conv3(x, edge_index))
                x = F.relu(self.conv4(x, edge_index))
                x = global_add_pool(x, batch)
                x = F.relu(self.lin1(x))
                x = self.lin2(x)
                return x
        
        # Load model
        if not os.path.exists(MODEL_PATH):
            print(f"   Model not found at {MODEL_PATH}, using heuristics")
            return heuristic_classify(functions)
        
        model = SOTA_GIN()
        model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
        model.eval()
        print(f"   Loaded model: {MODEL_PATH}")
        
        # Opcode mapping
        opcode_map = {
            "MOV": 0, "ADD": 1, "SUB": 2, "XOR": 3, "LDR": 4,
            "STR": 5, "CMP": 6, "JMP": 7, "CALL": 8, "RET": 9,
            "AND": 10, "ORR": 11, "LSL": 12, "LSR": 13, "NOP": 14,
            "POP": 15, "PUSH": 16
        }
        
        # Classify each function
        classified = []
        
        for func in functions:
            graph = func.get("graph", {})
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])
            
            if not nodes:
                continue
            
            # Extract features
            node_features = []
            node_id_map = {}
            
            for idx, node in enumerate(nodes):
                node_id_map[node["id"]] = idx
                vec = [0.0] * 20
                
                for op in node.get("ops", []):
                    k = op.upper()
                    if k in opcode_map:
                        vec[opcode_map[k]] += 1
                
                vec[17] = 0.5  # Centrality placeholder
                vec[18] = float(node.get("fk", 0))
                vec[19] = float(node.get("fu", 0))
                node_features.append(vec)
            
            x = torch.tensor(node_features, dtype=torch.float)
            
            # Remap edges
            if edges:
                remapped = []
                for src, dst in edges:
                    if src in node_id_map and dst in node_id_map:
                        remapped.append([node_id_map[src], node_id_map[dst]])
                
                if remapped:
                    edge_index = torch.tensor(remapped, dtype=torch.long).t().contiguous()
                else:
                    edge_index = torch.empty((2, 0), dtype=torch.long)
            else:
                edge_index = torch.empty((2, 0), dtype=torch.long)
            
            # Inference
            batch = torch.zeros(x.size(0), dtype=torch.long)
            
            with torch.no_grad():
                logits = model(x, edge_index, batch)
                probs = F.softmax(logits, dim=-1).numpy()[0]
                class_id = int(probs.argmax())
                confidence = float(probs.max())
            
            func["class_id"] = class_id
            func["class_name"] = CRYPTO_CLASSES.get(class_id, "Unknown")
            func["confidence"] = round(confidence, 4)
            func["probabilities"] = {
                CRYPTO_CLASSES.get(i, f"Class_{i}"): round(float(p), 4)
                for i, p in enumerate(probs)
            }
            
            classified.append(func)
        
        # Summary
        crypto_count = sum(1 for f in classified if f["class_id"] > 0)
        print(f"   Classified {len(classified)} functions")
        print(f"  → Crypto detected: {crypto_count} functions")
        
        return classified
        
    except ImportError as e:
        print(f"   PyTorch not available: {e}")
        print("  → Falling back to heuristic classification")
        return heuristic_classify(functions)


def heuristic_classify(functions):
    """Fallback heuristic classification when model unavailable."""
    patterns = [
        (["kyber", "dilithium", "falcon", "lms"], 9, "Post-Quantum"),
        (["xor_cipher", "otp"], 8, "XOR Cipher"),
        (["drbg", "entropy", "prng", "random"], 7, "PRNG"),
        (["pbkdf", "hkdf", "kdf", "derive", "scrypt"], 6, "KDF"),
        (["hmac", "cmac", "gmac", "poly1305", "mac"], 5, "Auth/MAC"),
        (["rsa", "ecc", "ecdsa", "ecdh", "sign", "verify"], 4, "Public Key"),
        (["chacha", "salsa", "rc4", "stream"], 3, "Stream Cipher"),
        (["sha", "md5", "hash", "digest", "blake", "ripemd"], 2, "Hash Function"),
        (["aes", "des", "encrypt", "decrypt", "cipher", "block", "camellia"], 1, "AES/Block Cipher"),
    ]
    
    for func in functions:
        name = func.get("name", "").lower()
        classified = False
        
        for keywords, class_id, class_name in patterns:
            if any(k in name for k in keywords):
                func["class_id"] = class_id
                func["class_name"] = class_name
                func["confidence"] = 0.75
                classified = True
                break
        
        if not classified:
            func["class_id"] = 0
            func["class_name"] = "Non-Crypto"
            func["confidence"] = 0.70
    
    return functions


# =============================================================================
# Step 4: Protocol Detection
# =============================================================================

def detect_protocols(classifications):
    """
    Detect high-level crypto protocols from primitive classifications.
    
    Input: Classified functions with crypto types
    Output: List of detected protocols with confidence
    """
    print(f"\n{'='*60}")
    print("STEP 4: Protocol Detection")
    print(f"{'='*60}")
    
    # Protocol signatures
    signatures = {
        "TLS_HANDSHAKE": {
            "required": ["AES/Block Cipher", "Hash Function"],
            "optional": ["Public Key", "Auth/MAC", "KDF"],
            "min_match": 2,
            "description": "TLS/SSL secure communication"
        },
        "SSH_PROTOCOL": {
            "required": ["Stream Cipher", "Hash Function"],
            "optional": ["Public Key", "Auth/MAC"],
            "min_match": 2,
            "description": "SSH secure shell protocol"
        },
        "KEY_EXCHANGE": {
            "required": ["Public Key"],
            "optional": ["Hash Function", "KDF"],
            "min_match": 1,
            "description": "Diffie-Hellman/ECDH key exchange"
        },
        "DIGITAL_SIGNATURE": {
            "required": ["Hash Function", "Public Key"],
            "optional": [],
            "min_match": 2,
            "description": "RSA/ECDSA digital signature"
        },
        "SECURE_BOOT": {
            "required": ["Hash Function", "Public Key"],
            "optional": [],
            "min_match": 2,
            "description": "Firmware signature verification"
        },
        "AUTHENTICATED_ENCRYPTION": {
            "required": ["AES/Block Cipher", "Auth/MAC"],
            "optional": [],
            "min_match": 2,
            "description": "AES-GCM or ChaCha20-Poly1305"
        },
        "PASSWORD_HASHING": {
            "required": ["KDF", "Hash Function"],
            "optional": ["PRNG"],
            "min_match": 2,
            "description": "PBKDF2/Argon2 password derivation"
        },
        "POST_QUANTUM_CRYPTO": {
            "required": ["Post-Quantum"],
            "optional": ["Hash Function"],
            "min_match": 1,
            "description": "Kyber/Dilithium post-quantum crypto"
        }
    }
    
    # Count detected classes
    from collections import Counter
    class_counts = Counter()
    class_functions = {}
    
    for func in classifications:
        class_name = func.get("class_name", "Unknown")
        if class_name != "Non-Crypto":
            class_counts[class_name] += 1
            if class_name not in class_functions:
                class_functions[class_name] = []
            class_functions[class_name].append(func["name"])
    
    detected_classes = set(class_counts.keys())
    detected_protocols = []
    
    # Check each protocol signature
    for proto_name, sig in signatures.items():
        required = set(sig["required"])
        optional = set(sig.get("optional", []))
        min_match = sig.get("min_match", len(required))
        
        required_matches = required & detected_classes
        optional_matches = optional & detected_classes
        total_matches = len(required_matches) + len(optional_matches)
        
        if len(required_matches) >= len(required) or len(required_matches) >= min_match:
            if total_matches >= min_match:
                confidence = min(1.0, total_matches / (len(required) + len(optional) * 0.5))
                
                evidence = []
                for cls in required_matches | optional_matches:
                    evidence.extend(class_functions.get(cls, [])[:3])
                
                detected_protocols.append({
                    "name": proto_name,
                    "description": sig.get("description", ""),
                    "confidence": round(confidence, 3),
                    "matched_classes": list(required_matches | optional_matches),
                    "evidence_functions": evidence[:10]
                })
    
    detected_protocols.sort(key=lambda x: -x["confidence"])
    
    print(f"   Detected {len(detected_protocols)} protocols")
    for proto in detected_protocols:
        print(f"    • {proto['name']} ({proto['confidence']*100:.0f}%)")
    
    return detected_protocols


# =============================================================================
# Step 5: Symbolic Verification (Angr)
# =============================================================================

def symbolic_verify(classifications, binary_path, detected_arch=None):
    """
    Perform symbolic execution on high-confidence functions.
    
    Uses Angr with architecture-aware loading to detect:
    - XOR chains (cipher operations)
    - S-box lookups (substitution tables)
    - Rotation patterns (key schedules)
    - Protocol context (TLS, SSH, etc.)
    
    Args:
        classifications: Classified functions from GNN
        binary_path: Path to binary file
        detected_arch: Architecture from detection (e.g., "ARM64", "x86")
    
    Returns:
        List of verified functions with protocol context
    """
    print(f"\n{'='*60}")
    print("STEP 5: Symbolic Verification (Angr)")
    print(f"{'='*60}")
    
    high_confidence = [f for f in classifications if f.get("confidence", 0) > 0.80]
    print(f"  High-confidence functions: {len(high_confidence)}")
    
    # Use our symbolic_verify module
    try:
        from symbolic_verify import get_verifier, verify_functions, check_angr_status
        
        # Check Angr status
        status = check_angr_status()
        if status["available"]:
            print(f"  Angr version: {status['version']}")
            if detected_arch:
                print(f"  Using architecture: {detected_arch}")
        else:
            print("  Angr not available, using heuristic verification")
        
        # Run verification with architecture hint
        verified_results = verify_functions(
            high_confidence,
            binary_path=binary_path,
            detected_arch=detected_arch,
            confidence_threshold=0.80
        )
        
        print(f"  Verified {len(verified_results)} functions")
        
        # Add protocol context for display
        for result in verified_results:
            protocol = result.get("protocol", "unknown")
            if protocol != "unknown":
                result["protocol_context"] = protocol.upper().replace("_", " ")
        
        return verified_results
        
    except ImportError as e:
        print(f"  Could not import symbolic_verify module: {e}")
        print("  Falling back to inline heuristic verification")
        
        # Inline heuristic fallback
        verified_results = []
        for func in high_confidence[:10]:
            name = func.get("name", "").lower()
            class_id = func.get("class_id", 0)
            
            context = None
            if "key" in name and "sched" in name:
                context = "KEY_SCHEDULE"
            elif "sign" in name or "verify" in name:
                context = "SIGNATURE_OPERATION"
            elif "handshake" in name or "hello" in name:
                context = "TLS_HANDSHAKE_STATE"
            elif "encrypt" in name or "decrypt" in name:
                context = "SYMMETRIC_ENCRYPTION"
            elif "hash" in name or "digest" in name:
                context = "HASH_COMPUTATION"
            elif class_id == 1:
                context = "BLOCK_CIPHER"
            elif class_id == 2:
                context = "HASH_CHAIN"
            elif class_id == 5:
                context = "MAC"
            
            if context:
                verified_results.append({
                    "function_name": func.get("name"),
                    "function_address": func.get("entry", "0x0"),
                    "verified": True,
                    "protocol": context.lower(),
                    "confidence": func.get("confidence", 0.5),
                    "details": {"method": "heuristic_fallback"}
                })
        
        return verified_results


# =============================================================================
# Step 6: Result Aggregation
# =============================================================================

def aggregate_results(binary_path, classifications, protocols, verifications):
    """
    Aggregate all analysis results into final report.
    """
    print(f"\n{'='*60}")
    print("STEP 6: Result Aggregation")
    print(f"{'='*60}")
    
    # Compute summary stats
    total_functions = len(classifications)
    crypto_functions = [f for f in classifications if f.get("class_id", 0) > 0]
    
    # Group by class
    class_summary = {}
    for func in classifications:
        cls = func.get("class_name", "Unknown")
        if cls not in class_summary:
            class_summary[cls] = []
        class_summary[cls].append({
            "name": func.get("name"),
            "confidence": func.get("confidence"),
            "address": func.get("entry")
        })
    
    result = {
        "metadata": {
            "binary": os.path.basename(binary_path),
            "binary_path": binary_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_functions": total_functions,
            "crypto_functions": len(crypto_functions)
        },
        "summary": {
            "crypto_detected": len(crypto_functions) > 0,
            "crypto_count": len(crypto_functions),
            "protocols_detected": len(protocols),
            "class_distribution": {k: len(v) for k, v in class_summary.items()}
        },
        "classifications": classifications,
        "protocols": protocols,
        "verifications": verifications,
        "class_summary": class_summary
    }
    
    print(f"   Report generated")
    print(f"  → Total functions: {total_functions}")
    print(f"  → Crypto functions: {len(crypto_functions)}")
    print(f"  → Protocols detected: {len(protocols)}")
    
    return result


# =============================================================================
# Main Entry Point
# =============================================================================

def analyze(binary_path, output_path=None, is_firmware=False):
    """
    Run complete analysis pipeline.
    
    Args:
        binary_path: Path to binary file
        output_path: Optional path for JSON report
        is_firmware: If True, extract firmware first with binwalk
        
    Returns:
        Analysis result dict
    """
    print("\n" + "="*60)
    print("  CRYPTOHUNTER - AI/ML Crypto Detection Pipeline")
    print("="*60)
    print(f"  Input: {binary_path}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if not os.path.exists(binary_path):
        print(f"\n Error: File not found: {binary_path}")
        return None
    
    # Step 0: Firmware extraction (if needed)
    binaries_to_analyze = [binary_path]
    
    if is_firmware or is_firmware_image(binary_path):
        print("\n[*] Detected firmware image, extracting with binwalk...")
        extract_dir = os.path.join(TEMP_DIR, os.path.basename(binary_path) + "_extracted")
        binaries_to_analyze = extract_firmware_with_binwalk(binary_path, extract_dir)
    
    # Analyze each extracted binary
    all_results = []
    
    for binary in binaries_to_analyze:
        print(f"\n[*] Analyzing: {os.path.basename(binary)}")
        
        # Step 0.5: Detect architecture BEFORE Ghidra analysis
        detected_arch = None
        try:
            # Import our architecture detector
            import sys
            if BASE_DIR not in sys.path:
                sys.path.insert(0, BASE_DIR)
            from standalone import detect_architecture_detailed
            
            arch_result = detect_architecture_detailed(binary)
            if arch_result and arch_result.get('final', {}).get('architecture') != 'Unknown':
                final = arch_result.get('final', {})
                detected_arch = final.get('architecture')
                confidence = final.get('confidence', 0)
                print(f"  Architecture detected: {detected_arch} ({confidence}% confidence)")
                
                # Add bits/endian if needed
                if final.get('bits') == 64 and '/64-bit' not in detected_arch:
                    detected_arch = f"{detected_arch}/64-bit"
                if final.get('endian') == 'BE' and '/BE' not in detected_arch:
                    detected_arch = f"{detected_arch}/BE"
        except ImportError:
            print("  Architecture detection module not available")
        except Exception as e:
            print(f"  Architecture detection failed: {e}")
        
        # Step 1: Ghidra extraction (with detected architecture)
        temp_dir = os.path.join(TEMP_DIR, os.path.basename(binary))
        functions = extract_graph_with_ghidra(binary, temp_dir, architecture=detected_arch)
        
        if not functions:
            print(f"     No functions extracted from {os.path.basename(binary)}")
            continue
    
        # Step 2: Fast filter
        suspicious = fast_filter_functions(functions)
        
        # Step 3: GNN classification  
        classified = classify_with_gnn(suspicious)
        
        # Step 4: Protocol detection
        protocols = detect_protocols(classified)
        
        # Step 5: Symbolic verification (with detected architecture)
        verifications = symbolic_verify(classified, binary, detected_arch=detected_arch)
        
        # Step 6: Aggregate results
        result = aggregate_results(binary, classified, protocols, verifications)
        all_results.append(result)
    
    if not all_results:
        print("\n No functions extracted from any binary. Analysis aborted.")
        return None
    
    # Merge results if multiple binaries
    if len(all_results) == 1:
        final_result = all_results[0]
    else:
        final_result = {
            "metadata": {
                "input": binary_path,
                "analysis_timestamp": datetime.now().isoformat(),
                "binaries_analyzed": len(all_results)
            },
            "binaries": all_results
        }
    
    # Save output
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(final_result, f, indent=2)
        print(f"\n Report saved to: {output_path}")
    
    # Print final summary
    print("\n" + "="*60)
    print("  ANALYSIS COMPLETE")
    print("="*60)
    
    return final_result


def main():
    parser = argparse.ArgumentParser(
        description="CryptoHunter - AI/ML Crypto Detection Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_full_analysis.py firmware.bin
  python run_full_analysis.py firmware.bin --firmware   # Force firmware extraction
  python run_full_analysis.py libaes.o --output report.json
        """
    )
    parser.add_argument("binary", help="Path to binary file to analyze")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument("--firmware", "-f", action="store_true",
                       help="Force firmware extraction with binwalk")
    
    args = parser.parse_args()
    
    output = args.output or f"{os.path.basename(args.binary)}_report.json"
    
    result = analyze(args.binary, output, is_firmware=args.firmware)
    
    if result:
        print(f"\n{'='*60}")
        print("DETECTED CRYPTO PRIMITIVES:")
        print(f"{'='*60}")
        
        # Handle single or multiple binary results
        if 'binaries' in result:
            for bin_result in result['binaries']:
                print(f"\n[{bin_result['metadata']['binary']}]")
                for cls, funcs in bin_result.get("class_summary", {}).items():
                    if cls != "Non-Crypto" and funcs:
                        print(f"  {cls}: {len(funcs)} functions")
        else:
            for cls, funcs in result.get("class_summary", {}).items():
                if cls != "Non-Crypto" and funcs:
                    print(f"\n{cls}:")
                    for f in funcs[:5]:
                        print(f"  • {f['name']} ({f['confidence']*100:.0f}%)")
            
            if result.get("protocols"):
                print(f"\n{'='*60}")
                print("DETECTED PROTOCOLS:")
                print(f"{'='*60}")
                for proto in result["protocols"]:
                    print(f"\n{proto['name']} ({proto['confidence']*100:.0f}%)")
                    print(f"  {proto['description']}")

if __name__ == "__main__":
    main()
