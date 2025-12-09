"""
Detailed Crypto Analysis Module
Provides comprehensive metadata for each detected algorithm, protocol, and architecture.
"""

import os
import math
import struct
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


# =============================================================================
# Entropy Calculation
# =============================================================================

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0-8 bits)."""
    if not data:
        return 0.0
    
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    length = len(data)
    entropy = 0.0
    
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return round(entropy, 4)


def get_entropy_classification(entropy: float) -> str:
    """Classify entropy level."""
    if entropy < 3.0:
        return "Low (likely text/code)"
    elif entropy < 5.0:
        return "Medium (mixed data)"
    elif entropy < 7.0:
        return "High (compressed/structured)"
    else:
        return "Very High (encrypted/random)"


def analyze_entropy_regions(data: bytes, block_size: int = 1024) -> List[Dict]:
    """Analyze entropy in blocks and find high-entropy regions."""
    regions = []
    
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < 256:  # Skip small blocks
            continue
        
        entropy = calculate_shannon_entropy(block)
        regions.append({
            "offset": i,
            "offset_hex": f"0x{i:08X}",
            "size": len(block),
            "entropy": entropy,
            "classification": get_entropy_classification(entropy)
        })
    
    return regions


# =============================================================================
# Algorithm Detection Details
# =============================================================================

# Detailed algorithm information database
ALGORITHM_DATABASE = {
    # Block Ciphers
    "AES": {
        "full_name": "Advanced Encryption Standard",
        "type": "Block Cipher",
        "class_id": 1,
        "block_size": 128,
        "key_sizes": [128, 192, 256],
        "modes": ["ECB", "CBC", "CTR", "GCM", "CCM"],
        "security_notes": "NIST approved, widely used standard",
        "detection_patterns": {
            "sbox": "S-box substitution table (256 bytes starting with 0x63, 0x7C...)",
            "rcon": "Round constants for key expansion",
            "inv_sbox": "Inverse S-box for decryption"
        }
    },
    "DES": {
        "full_name": "Data Encryption Standard",
        "type": "Block Cipher",
        "class_id": 1,
        "block_size": 64,
        "key_sizes": [56],
        "modes": ["ECB", "CBC"],
        "security_notes": "Deprecated - key too short (56-bit)",
        "detection_patterns": {
            "initial_permutation": "IP table (64 values)",
            "sboxes": "8 S-boxes (6-bit to 4-bit)"
        }
    },
    "Blowfish": {
        "full_name": "Blowfish",
        "type": "Block Cipher",
        "class_id": 1,
        "block_size": 64,
        "key_sizes": [32, 448],
        "modes": ["ECB", "CBC", "CTR"],
        "security_notes": "Considered secure but superseded by Twofish",
        "detection_patterns": {
            "parray": "P-array (18 x 32-bit values starting with 0x243F6A88)",
            "sboxes": "4 S-boxes (256 x 32-bit each)"
        }
    },
    
    # Hash Functions
    "SHA-256": {
        "full_name": "Secure Hash Algorithm 256-bit",
        "type": "Hash Function",
        "class_id": 2,
        "output_size": 256,
        "block_size": 512,
        "security_notes": "NIST approved, part of SHA-2 family",
        "detection_patterns": {
            "k_constants": "K constants (64 x 32-bit starting with 0x428A2F98)",
            "init_vectors": "Initial hash values (8 x 32-bit)"
        }
    },
    "SHA-512": {
        "full_name": "Secure Hash Algorithm 512-bit",
        "type": "Hash Function",
        "class_id": 2,
        "output_size": 512,
        "block_size": 1024,
        "security_notes": "NIST approved, stronger SHA-2 variant",
        "detection_patterns": {
            "k_constants": "K constants (80 x 64-bit)"
        }
    },
    "MD5": {
        "full_name": "Message Digest 5",
        "type": "Hash Function",
        "class_id": 2,
        "output_size": 128,
        "block_size": 512,
        "security_notes": "BROKEN - collision attacks exist, avoid for security",
        "detection_patterns": {
            "t_values": "T values (64 values starting with 0xD76AA478)"
        }
    },
    
    # Stream Ciphers
    "ChaCha20": {
        "full_name": "ChaCha20 Stream Cipher",
        "type": "Stream Cipher",
        "class_id": 3,
        "key_sizes": [256],
        "nonce_size": 96,
        "security_notes": "Modern, secure, used in TLS 1.3",
        "detection_patterns": {
            "sigma": "Sigma constants ('expand 32-byte k')",
            "quarter_round": "Quarter round operations"
        }
    },
    "RC4": {
        "full_name": "Rivest Cipher 4",
        "type": "Stream Cipher",
        "class_id": 3,
        "key_sizes": [40, 128],
        "security_notes": "BROKEN - multiple attacks, do not use",
        "detection_patterns": {
            "sbox_init": "S-box initialization (256-byte permutation)"
        }
    },
    
    # Public Key
    "RSA": {
        "full_name": "Rivest-Shamir-Adleman",
        "type": "Public Key",
        "class_id": 4,
        "key_sizes": [2048, 4096],
        "security_notes": "Slow for large data, use for key exchange",
        "detection_patterns": {
            "modulus": "Large prime numbers (n, p, q)",
            "exponent": "Public exponent (commonly 65537)"
        }
    },
    
    # MAC
    "HMAC": {
        "full_name": "Hash-based Message Authentication Code",
        "type": "MAC",
        "class_id": 5,
        "security_notes": "Provides authenticity and integrity",
        "detection_patterns": {
            "ipad_opad": "Inner/outer padding constants (0x36, 0x5C)"
        }
    },
    
    # KDF
    "PBKDF2": {
        "full_name": "Password-Based Key Derivation Function 2",
        "type": "KDF",
        "class_id": 6,
        "security_notes": "Use with high iteration count (100k+)",
        "detection_patterns": {
            "iteration_loop": "HMAC iteration structure"
        }
    },
    
    # PRNG
    "Mersenne Twister": {
        "full_name": "Mersenne Twister PRNG (MT19937)",
        "type": "PRNG",
        "class_id": 7,
        "security_notes": "NOT cryptographically secure - predictable",
        "detection_patterns": {
            "magic_constant": "Magic constant 0x9908B0DF"
        }
    }
}


@dataclass
class AlgorithmDetail:
    """Detailed information about a detected algorithm."""
    # Basic identification
    name: str
    full_name: str
    algorithm_type: str
    class_id: int
    class_name: str
    
    # Detection confidence
    confidence: float
    confidence_level: str  # "High", "Medium", "Low"
    
    # Detection method
    detection_method: str
    detection_indicator: str
    pattern_matched: str
    
    # Location in binary
    offset: int
    offset_hex: str
    size: int
    end_offset: int
    end_offset_hex: str
    
    # Entropy analysis
    local_entropy: float
    entropy_classification: str
    
    # Context data
    context_bytes_hex: str
    context_bytes_ascii: str
    
    # Algorithm properties
    key_sizes: List[int]
    block_size: Optional[int]
    security_notes: str
    
    # Cross-references
    related_detections: List[str]
    possible_protocol: Optional[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


def get_hex_context(data: bytes, offset: int, size: int = 32) -> Tuple[str, str]:
    """Get hex and ASCII context around an offset."""
    start = max(0, offset)
    end = min(len(data), offset + size)
    context = data[start:end]
    
    hex_str = " ".join(f"{b:02X}" for b in context)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in context)
    
    return hex_str, ascii_str


def get_confidence_level(confidence: float) -> str:
    """Convert confidence to human-readable level."""
    if confidence >= 0.90:
        return "Very High"
    elif confidence >= 0.75:
        return "High"
    elif confidence >= 0.60:
        return "Medium"
    elif confidence >= 0.40:
        return "Low"
    else:
        return "Very Low"


def create_algorithm_detail(
    name: str,
    class_id: int,
    class_name: str,
    confidence: float,
    indicator: str,
    data: bytes,
    offset: int = 0,
    pattern_matched: str = ""
) -> AlgorithmDetail:
    """Create a detailed algorithm detection report."""
    
    # Get algorithm info from database
    algo_info = ALGORITHM_DATABASE.get(name.split("-")[0].upper(), {})
    if not algo_info:
        # Try to find by checking all entries
        for algo_name, info in ALGORITHM_DATABASE.items():
            if algo_name.lower() in name.lower():
                algo_info = info
                break
    
    # Get context bytes
    hex_context, ascii_context = get_hex_context(data, offset)
    
    # Calculate local entropy
    local_data = data[max(0, offset):min(len(data), offset + 256)]
    local_entropy = calculate_shannon_entropy(local_data)
    
    return AlgorithmDetail(
        name=name,
        full_name=algo_info.get("full_name", name),
        algorithm_type=algo_info.get("type", class_name),
        class_id=class_id,
        class_name=class_name,
        confidence=round(confidence, 4),
        confidence_level=get_confidence_level(confidence),
        detection_method=indicator.split()[0] if indicator else "Pattern Match",
        detection_indicator=indicator,
        pattern_matched=pattern_matched or algo_info.get("detection_patterns", {}).get("sbox", "Binary pattern"),
        offset=offset,
        offset_hex=f"0x{offset:08X}",
        size=256,  # Default pattern size
        end_offset=offset + 256,
        end_offset_hex=f"0x{offset + 256:08X}",
        local_entropy=local_entropy,
        entropy_classification=get_entropy_classification(local_entropy),
        context_bytes_hex=hex_context,
        context_bytes_ascii=ascii_context,
        key_sizes=algo_info.get("key_sizes", []),
        block_size=algo_info.get("block_size"),
        security_notes=algo_info.get("security_notes", ""),
        related_detections=[],
        possible_protocol=None
    )


# =============================================================================
# Protocol Detection Details
# =============================================================================

PROTOCOL_DATABASE = {
    "TLS": {
        "full_name": "Transport Layer Security",
        "versions": ["1.0", "1.1", "1.2", "1.3"],
        "purpose": "Secure communication over network",
        "typical_algorithms": ["AES", "SHA-256", "RSA", "ECDHE"],
        "cipher_suites": [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
        ]
    },
    "SSH": {
        "full_name": "Secure Shell",
        "versions": ["2.0"],
        "purpose": "Secure remote access",
        "typical_algorithms": ["AES", "ChaCha20", "RSA", "Ed25519"],
        "kex_algorithms": ["curve25519-sha256", "ecdh-sha2-nistp256"]
    },
    "IPsec": {
        "full_name": "Internet Protocol Security",
        "purpose": "VPN and network-level security",
        "typical_algorithms": ["AES", "SHA-256", "HMAC"],
        "modes": ["Transport", "Tunnel"]
    }
}


@dataclass
class ProtocolDetail:
    """Detailed information about a detected protocol."""
    name: str
    full_name: str
    confidence: float
    confidence_level: str
    
    # Detection basis
    detection_basis: str
    component_algorithms: List[str]
    
    # Protocol specifics
    probable_version: Optional[str]
    purpose: str
    
    # Cipher suite (for TLS)
    probable_cipher_suite: Optional[str]
    key_exchange: Optional[str]
    
    # Evidence
    string_matches: List[str]
    algorithm_combinations: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


def detect_protocols_detailed(classifications: List[Dict]) -> List[ProtocolDetail]:
    """Detect protocols with detailed information."""
    protocols = []
    
    # Get class IDs present
    class_ids = {c.get("class_id", 0) for c in classifications}
    class_names = [c.get("class_name", "") for c in classifications]
    names = [c.get("name", "").lower() for c in classifications]
    
    # Check for TLS/SSL
    has_block_cipher = 1 in class_ids
    has_hash = 2 in class_ids
    has_pubkey = 4 in class_ids
    has_mac = 5 in class_ids
    
    # TLS detection
    if has_block_cipher and has_hash:
        confidence = 0.70
        basis = ["Block cipher + Hash function detected"]
        
        if has_pubkey:
            confidence = 0.85
            basis.append("Public key cryptography present")
        
        if has_mac:
            confidence = 0.90
            basis.append("MAC present (likely AEAD)")
        
        # Check for TLS-specific strings
        tls_strings = [n for n in names if "tls" in n or "ssl" in n or "handshake" in n]
        if tls_strings:
            confidence = min(0.95, confidence + 0.05)
            basis.append(f"TLS/SSL strings: {', '.join(tls_strings[:3])}")
        
        protocols.append(ProtocolDetail(
            name="TLS",
            full_name="Transport Layer Security",
            confidence=round(confidence, 2),
            confidence_level=get_confidence_level(confidence),
            detection_basis=" | ".join(basis),
            component_algorithms=list(set(class_names)),
            probable_version="1.2/1.3" if confidence > 0.80 else "Unknown",
            purpose="Secure network communication (HTTPS, etc.)",
            probable_cipher_suite="TLS_ECDHE_RSA_WITH_AES_*_GCM_SHA*" if has_pubkey else "TLS_PSK_WITH_AES_*",
            key_exchange="ECDHE" if has_pubkey else "PSK",
            string_matches=tls_strings[:5],
            algorithm_combinations=["AES+SHA256+RSA", "AES+SHA256"] if has_pubkey else ["AES+SHA256"]
        ))
    
    # SSH detection
    ssh_strings = [n for n in names if "ssh" in n or "kex" in n]
    if has_pubkey and ssh_strings:
        protocols.append(ProtocolDetail(
            name="SSH",
            full_name="Secure Shell",
            confidence=0.80,
            confidence_level="High",
            detection_basis="Public key + SSH-related strings",
            component_algorithms=list(set(class_names)),
            probable_version="2.0",
            purpose="Secure remote access",
            probable_cipher_suite=None,
            key_exchange="curve25519-sha256 or ecdh-sha2-nistp256",
            string_matches=ssh_strings[:5],
            algorithm_combinations=["Ed25519/RSA + AES + SHA256"]
        ))
    
    return protocols


# =============================================================================
# Architecture Detection Details
# =============================================================================

@dataclass
class ArchitectureDetail:
    """Detailed information about detected architecture."""
    architecture: str
    full_name: str
    confidence: float
    confidence_level: str
    
    # Basic properties
    bits: int
    endianness: str
    instruction_set: str
    
    # Detection methods
    primary_method: str
    capstone_result: Optional[Dict]
    header_result: Optional[Dict]
    heuristic_indicators: List[str]
    
    # Disassembly quality
    coverage_score: float
    continuity_score: float
    
    # Entry point
    entry_point: Optional[int]
    entry_point_hex: Optional[str]
    
    # Ghidra mapping
    ghidra_processor: str
    
    # Sample instructions
    sample_disassembly: List[str]
    
    # Function prologues found
    prologue_count: int
    prologue_examples: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


ARCHITECTURE_INFO = {
    "ARM64": {
        "full_name": "ARM 64-bit (AArch64)",
        "instruction_set": "ARMv8-A",
        "common_prologue": "STP X29, X30, [SP, #-0x10]!",
        "ghidra": "AARCH64:LE:64:v8A"
    },
    "ARM32": {
        "full_name": "ARM 32-bit (AArch32)",
        "instruction_set": "ARMv7-A",
        "common_prologue": "PUSH {R4-R11, LR}",
        "ghidra": "ARM:LE:32:v7"
    },
    "x86": {
        "full_name": "Intel x86 32-bit",
        "instruction_set": "IA-32",
        "common_prologue": "PUSH EBP; MOV EBP, ESP",
        "ghidra": "x86:LE:32:default"
    },
    "x86-64": {
        "full_name": "AMD64 / Intel x64",
        "instruction_set": "x86-64",
        "common_prologue": "PUSH RBP; MOV RBP, RSP",
        "ghidra": "x86:LE:64:default"
    },
    "MIPS-BE": {
        "full_name": "MIPS 32-bit Big Endian",
        "instruction_set": "MIPS32",
        "common_prologue": "ADDIU SP, SP, -0x20",
        "ghidra": "MIPS:BE:32:default"
    },
    "MIPS-LE": {
        "full_name": "MIPS 32-bit Little Endian",
        "instruction_set": "MIPS32",
        "common_prologue": "ADDIU SP, SP, -0x20",
        "ghidra": "MIPS:LE:32:default"
    }
}


def create_architecture_detail(arch_result: Dict) -> ArchitectureDetail:
    """Create detailed architecture report."""
    final = arch_result.get("final", {})
    method1 = arch_result.get("method_1", {})
    method2 = arch_result.get("method_2", {})
    
    arch = final.get("architecture", "Unknown")
    arch_info = ARCHITECTURE_INFO.get(arch, {})
    
    return ArchitectureDetail(
        architecture=arch,
        full_name=arch_info.get("full_name", arch),
        confidence=final.get("confidence", 0) / 100 if final.get("confidence", 0) > 1 else final.get("confidence", 0),
        confidence_level=get_confidence_level(final.get("confidence", 0) / 100 if final.get("confidence", 0) > 1 else final.get("confidence", 0)),
        bits=final.get("bits", 32),
        endianness="Little Endian" if final.get("endian", "LE") == "LE" else "Big Endian",
        instruction_set=arch_info.get("instruction_set", "Unknown"),
        primary_method=method1.get("method", "Capstone") if method1.get("confidence", 0) > method2.get("confidence", 0) else method2.get("method", "Header"),
        capstone_result={
            "architecture": method1.get("architecture"),
            "confidence": method1.get("confidence"),
            "coverage": method1.get("details", {}).get("coverage"),
            "continuity": method1.get("details", {}).get("continuity")
        } if method1 else None,
        header_result={
            "architecture": method2.get("architecture"),
            "confidence": method2.get("confidence"),
            "source": method2.get("details", {}).get("source")
        } if method2 else None,
        heuristic_indicators=final.get("indicators", []),
        coverage_score=method1.get("details", {}).get("coverage", 0) if method1 else 0,
        continuity_score=method1.get("details", {}).get("continuity", 0) if method1 else 0,
        entry_point=None,
        entry_point_hex=None,
        ghidra_processor=arch_info.get("ghidra", "Unknown"),
        sample_disassembly=[],
        prologue_count=0,
        prologue_examples=[arch_info.get("common_prologue", "")]
    )


# =============================================================================
# Complete Detailed Analysis
# =============================================================================

@dataclass
class DetailedAnalysisReport:
    """Complete detailed analysis report."""
    # Metadata
    filename: str
    file_size: int
    file_hash: str
    analysis_timestamp: str
    analysis_duration: float
    
    # Architecture
    architecture: ArchitectureDetail
    
    # Algorithms
    algorithms_detected: List[AlgorithmDetail]
    algorithms_count: int
    
    # Protocols
    protocols_detected: List[ProtocolDetail]
    protocols_count: int
    
    # Entropy
    global_entropy: float
    entropy_classification: str
    high_entropy_regions: List[Dict]
    
    # Summary
    crypto_detected: bool
    primary_crypto_type: str
    security_assessment: str
    
    def to_dict(self) -> Dict:
        return {
            "metadata": {
                "filename": self.filename,
                "file_size": self.file_size,
                "file_hash": self.file_hash,
                "analysis_timestamp": self.analysis_timestamp,
                "analysis_duration": self.analysis_duration
            },
            "architecture": self.architecture.to_dict(),
            "algorithms": {
                "count": self.algorithms_count,
                "detections": [a.to_dict() for a in self.algorithms_detected]
            },
            "protocols": {
                "count": self.protocols_count,
                "detections": [p.to_dict() for p in self.protocols_detected]
            },
            "entropy_analysis": {
                "global_entropy": self.global_entropy,
                "classification": self.entropy_classification,
                "high_entropy_regions": self.high_entropy_regions
            },
            "summary": {
                "crypto_detected": self.crypto_detected,
                "primary_crypto_type": self.primary_crypto_type,
                "security_assessment": self.security_assessment
            }
        }


def run_detailed_analysis(file_path: str) -> DetailedAnalysisReport:
    """Run comprehensive detailed analysis on a binary file."""
    import hashlib
    import time
    from pathlib import Path
    
    start_time = time.time()
    
    # Read file
    file_path = Path(file_path)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Calculate hash
    file_hash = hashlib.sha256(data).hexdigest()
    
    # Architecture detection
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        from standalone import detect_architecture_detailed
        arch_result = detect_architecture_detailed(str(file_path))
        arch_detail = create_architecture_detail(arch_result)
    except Exception as e:
        arch_detail = ArchitectureDetail(
            architecture="Unknown",
            full_name="Unknown",
            confidence=0,
            confidence_level="Unknown",
            bits=0,
            endianness="Unknown",
            instruction_set="Unknown",
            primary_method="None",
            capstone_result=None,
            header_result=None,
            heuristic_indicators=[],
            coverage_score=0,
            continuity_score=0,
            entry_point=None,
            entry_point_hex=None,
            ghidra_processor="Unknown",
            sample_disassembly=[],
            prologue_count=0,
            prologue_examples=[]
        )
    
    # Crypto detection with details
    try:
        from standalone import analyze_binary_heuristic
        crypto_found, classifications = analyze_binary_heuristic(str(file_path))
    except:
        crypto_found = False
        classifications = []
    
    # Create detailed algorithm reports
    algorithms = []
    for cls in classifications:
        if cls.get("class_id", 0) > 0:
            # Find offset in binary if possible
            indicator = cls.get("indicator", "")
            offset = 0
            
            # Try to find the pattern
            name = cls.get("name", "")
            
            algo_detail = create_algorithm_detail(
                name=name,
                class_id=cls.get("class_id", 0),
                class_name=cls.get("class_name", "Unknown"),
                confidence=cls.get("confidence", 0),
                indicator=indicator,
                data=data,
                offset=offset
            )
            algorithms.append(algo_detail)
    
    # Protocol detection
    protocols = detect_protocols_detailed(classifications)
    
    # Entropy analysis
    global_entropy = calculate_shannon_entropy(data)
    high_entropy = [r for r in analyze_entropy_regions(data) if r["entropy"] > 7.0]
    
    # Determine primary crypto type
    class_counts = {}
    for a in algorithms:
        t = a.algorithm_type
        class_counts[t] = class_counts.get(t, 0) + 1
    primary_type = max(class_counts, key=class_counts.get) if class_counts else "None"
    
    # Security assessment
    if not crypto_found:
        assessment = "No cryptographic implementations detected"
    elif any("BROKEN" in a.security_notes for a in algorithms):
        assessment = "WARNING: Deprecated/broken cryptographic algorithms detected"
    elif any(a.confidence > 0.85 for a in algorithms):
        assessment = "Strong cryptographic implementation detected"
    else:
        assessment = "Cryptographic patterns detected with moderate confidence"
    
    duration = time.time() - start_time
    
    return DetailedAnalysisReport(
        filename=file_path.name,
        file_size=len(data),
        file_hash=file_hash,
        analysis_timestamp=datetime.now().isoformat(),
        analysis_duration=round(duration, 3),
        architecture=arch_detail,
        algorithms_detected=algorithms,
        algorithms_count=len(algorithms),
        protocols_detected=protocols,
        protocols_count=len(protocols),
        global_entropy=global_entropy,
        entropy_classification=get_entropy_classification(global_entropy),
        high_entropy_regions=high_entropy[:10],  # Top 10
        crypto_detected=crypto_found,
        primary_crypto_type=primary_type,
        security_assessment=assessment
    )


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python detailed_analysis.py <binary_file>")
        sys.exit(1)
    
    report = run_detailed_analysis(sys.argv[1])
    print(json.dumps(report.to_dict(), indent=2))
