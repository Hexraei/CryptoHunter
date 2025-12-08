# infer_crypto.py - Standalone GNN Inference on Graph JSON
# Run trained model on pre-extracted Ghidra graphs
# Now with Z80/AVR/Xtensa/ARM Cortex architecture detection support
#
# Usage: python infer_crypto.py <graph.json> [--model model.pt] [--binary firmware.bin]

import os
import sys
import json
import argparse

# Architecture detection
try:
    from check_z80 import detect_z80
    from check_avr import detect_avr
    from check_xtensa import detect_xtensa
    from check_arm_cortex import detect_arm_cortex
    ARCH_DETECTION_AVAILABLE = True
except ImportError:
    ARCH_DETECTION_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

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

OPCODE_MAP = {
    "MOV": 0, "ADD": 1, "SUB": 2, "XOR": 3, "LDR": 4,
    "STR": 5, "CMP": 6, "JMP": 7, "CALL": 8, "RET": 9,
    "AND": 10, "ORR": 11, "LSL": 12, "LSR": 13, "NOP": 14,
    "POP": 15, "PUSH": 16
}


# =============================================================================
# Architecture Detection
# =============================================================================

def detect_architecture(binary_path):
    """
    Detect Z80/AVR/Xtensa/ARM Cortex architecture from binary file.
    
    Args:
        binary_path: Path to binary file
        
    Returns:
        Dict with arch, bits, endian, confidence
    """
    if not ARCH_DETECTION_AVAILABLE:
        return {'arch': 'unknown', 'bits': 0, 'endian': 'unknown', 'confidence': 0, 'error': 'detection modules not found'}
    
    if not os.path.exists(binary_path):
        return {'arch': 'unknown', 'bits': 0, 'endian': 'unknown', 'confidence': 0, 'error': 'file not found'}
    
    # Run all detectors
    z80_result = detect_z80(binary_path)
    avr_result = detect_avr(binary_path)
    xtensa_result = detect_xtensa(binary_path)
    arm_result = detect_arm_cortex(binary_path)
    
    z80_conf = z80_result.get('confidence', 0)
    avr_conf = avr_result.get('confidence', 0)
    xtensa_conf = xtensa_result.get('confidence', 0)
    arm_conf = arm_result.get('confidence', 0)
    
    # Find best match
    results = [
        (arm_conf, 'ARM/Cortex-M', arm_result, 32, 'little', arm_result.get('is_arm_cortex', False)),
        (xtensa_conf, 'Xtensa', xtensa_result, 32, 'little', xtensa_result.get('is_xtensa', False)),
        (avr_conf, 'AVR', avr_result, 8, 'little', avr_result.get('is_avr', False)),
        (z80_conf, 'Z80', z80_result, 8, 'little', z80_result.get('is_z80', False)),
    ]
    
    # Sort by confidence, descending
    results.sort(key=lambda x: x[0], reverse=True)
    
    for conf, arch, result, bits, endian, is_detected in results:
        if is_detected:
            return {
                'arch': arch,
                'bits': bits,
                'endian': endian,
                'confidence': round(conf, 3),
                'indicators': result.get('indicators', [])
            }
    
    # Return best guess even if below threshold
    best = results[0]
    if best[0] > 0:
        return {
            'arch': f'possibly_{best[1]}',
            'bits': best[3],
            'endian': best[4],
            'confidence': round(best[0], 3)
        }
    
    return {'arch': 'unknown', 'bits': 0, 'endian': 'unknown', 'confidence': 0}


# =============================================================================
# Inference Engine
# =============================================================================

class CryptoInference:
    """Run GNN model inference on graph data."""
    
    def __init__(self, model_path="sota_crypto_model.pt"):
        self.model_path = model_path
        self.model = None
        self.device = None
        self._load_model()
    
    def _load_model(self):
        """Load PyTorch model."""
        try:
            import torch
            import torch.nn.functional as F
            from torch_geometric.nn import GINConv, global_add_pool
            
            self.torch = torch
            self.F = F
            self.device = torch.device('cpu')
            
            HIDDEN_DIM = 128
            NUM_CLASSES = 10
            
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
            
            if os.path.exists(self.model_path):
                self.model = SOTA_GIN()
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                self.model.eval()
                print(f" Model loaded: {self.model_path}")
            else:
                print(f" Model not found: {self.model_path}")
                print("  Using heuristic classification")
                
        except ImportError as e:
            print(f" PyTorch dependencies missing: {e}")
            print("  Using heuristic classification")
    
    def infer(self, functions):
        """
        Run inference on list of functions.
        
        Args:
            functions: List of function dicts with 'graph' field
            
        Returns:
            List of classification results
        """
        results = []
        
        for func in functions:
            if self.model:
                result = self._model_infer(func)
            else:
                result = self._heuristic_infer(func)
            
            result["function_name"] = func.get("name", "unknown")
            result["address"] = func.get("entry", "0x0")
            results.append(result)
        
        return results
    
    def _model_infer(self, func):
        """Run model inference on single function."""
        graph = func.get("graph", {})
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        
        if not nodes:
            return {"class_id": 0, "class_name": "Non-Crypto", "confidence": 0.5}
        
        # Extract features
        node_features = []
        node_id_map = {}
        
        for idx, node in enumerate(nodes):
            node_id_map[node["id"]] = idx
            vec = [0.0] * 20
            
            for op in node.get("ops", []):
                k = op.upper()
                if k in OPCODE_MAP:
                    vec[OPCODE_MAP[k]] += 1
            
            vec[17] = 0.5  # Centrality
            vec[18] = float(node.get("fk", 0))
            vec[19] = float(node.get("fu", 0))
            node_features.append(vec)
        
        x = self.torch.tensor(node_features, dtype=self.torch.float)
        
        # Build edges
        if edges:
            remapped = []
            for src, dst in edges:
                if src in node_id_map and dst in node_id_map:
                    remapped.append([node_id_map[src], node_id_map[dst]])
            
            if remapped:
                edge_index = self.torch.tensor(remapped, dtype=self.torch.long).t().contiguous()
            else:
                edge_index = self.torch.empty((2, 0), dtype=self.torch.long)
        else:
            edge_index = self.torch.empty((2, 0), dtype=self.torch.long)
        
        # Inference
        batch = self.torch.zeros(x.size(0), dtype=self.torch.long)
        
        with self.torch.no_grad():
            logits = self.model(x, edge_index, batch)
            probs = self.F.softmax(logits, dim=-1).numpy()[0]
            class_id = int(probs.argmax())
            confidence = float(probs.max())
        
        return {
            "class_id": class_id,
            "class_name": CRYPTO_CLASSES.get(class_id, "Unknown"),
            "confidence": round(confidence, 4),
            "probabilities": {
                CRYPTO_CLASSES.get(i): round(float(p), 4)
                for i, p in enumerate(probs)
            }
        }
    
    def _heuristic_infer(self, func):
        """Fallback heuristic classification."""
        name = func.get("name", "").lower()
        
        patterns = [
            (["kyber", "dilithium", "falcon", "lms"], 9, "Post-Quantum"),
            (["drbg", "entropy", "prng", "random"], 7, "PRNG"),
            (["pbkdf", "hkdf", "kdf", "scrypt"], 6, "KDF"),
            (["hmac", "cmac", "gmac", "poly1305", "mac"], 5, "Auth/MAC"),
            (["rsa", "ecc", "ecdsa", "ecdh", "sign", "verify"], 4, "Public Key"),
            (["chacha", "salsa", "rc4"], 3, "Stream Cipher"),
            (["sha", "md5", "hash", "blake", "ripemd"], 2, "Hash Function"),
            (["aes", "des", "encrypt", "decrypt", "cipher"], 1, "AES/Block Cipher"),
        ]
        
        for keywords, class_id, class_name in patterns:
            if any(k in name for k in keywords):
                return {
                    "class_id": class_id,
                    "class_name": class_name,
                    "confidence": 0.75
                }
        
        return {
            "class_id": 0,
            "class_name": "Non-Crypto",
            "confidence": 0.70
        }


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run crypto classification on Ghidra graph JSON"
    )
    parser.add_argument("graph_json", help="Path to graph JSON file")
    parser.add_argument("--model", "-m", default="sota_crypto_model.pt",
                       help="Path to trained model")
    parser.add_argument("--binary", "-b", help="Original binary for architecture detection")
    parser.add_argument("--output", "-o", help="Output JSON path")
    parser.add_argument("--verbose", "-v", action="store_true")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.graph_json):
        print(f"Error: File not found: {args.graph_json}")
        sys.exit(1)
    
    # Load graph
    with open(args.graph_json, 'r') as f:
        data = json.load(f)
    
    # Handle different JSON formats
    if isinstance(data, list):
        functions = data
    elif isinstance(data, dict) and "functions" in data:
        functions = data["functions"]
    else:
        functions = [data]
    
    print(f"\nLoaded {len(functions)} functions from {args.graph_json}")
    
    # Architecture detection (optional)
    arch_info = None
    if args.binary:
        arch_info = detect_architecture(args.binary)
        if arch_info.get('arch') not in ['unknown', 'possibly_AVR', 'possibly_Z80']:
            print(f"\n Architecture: {arch_info['arch']} ({arch_info['bits']}-bit, {arch_info['endian']}-endian)")
            print(f"  Confidence: {arch_info['confidence']*100:.1f}%")
        elif arch_info.get('confidence', 0) > 0:
            print(f"\n? Possible architecture: {arch_info['arch']} (confidence: {arch_info['confidence']*100:.1f}%)")
    
    # Run inference
    engine = CryptoInference(args.model)
    results = engine.infer(functions)
    
    # Print results
    print("\n" + "="*60)
    print("CLASSIFICATION RESULTS")
    print("="*60)
    
    crypto_funcs = []
    
    for r in results:
        if r["class_id"] > 0:
            crypto_funcs.append(r)
            if args.verbose or len(results) <= 20:
                print(f"\n{r['function_name']}")
                print(f"  Class: {r['class_name']}")
                print(f"  Confidence: {r['confidence']*100:.1f}%")
    
    print(f"\n{'='*60}")
    print(f"SUMMARY: {len(crypto_funcs)} crypto functions detected out of {len(results)}")
    
    # Group by class
    from collections import Counter
    class_counts = Counter(r["class_name"] for r in results if r["class_id"] > 0)
    
    if class_counts:
        print("\nCrypto Distribution:")
        for cls, count in class_counts.most_common():
            print(f"  {cls}: {count}")
    
    # Save output
    if args.output:
        output = {
            "source": args.graph_json,
            "model": args.model,
            "architecture": arch_info,
            "total_functions": len(results),
            "crypto_functions": len(crypto_funcs),
            "results": results
        }
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
