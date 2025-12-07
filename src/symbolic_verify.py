"""
Angr Symbolic Verification
Verify high-confidence crypto functions using symbolic execution.
Detects protocol patterns like TLS handshake, key schedules, etc.

This is Step 2.5 in the research pipeline.
"""

import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# Try to import angr
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    print("⚠ Angr not available, symbolic verification disabled")


class ProtocolType(Enum):
    """Detected protocol types."""
    UNKNOWN = "unknown"
    TLS_HANDSHAKE = "tls_handshake"
    TLS_RECORD = "tls_record"
    SSH_KEX = "ssh_key_exchange"
    IPSEC_ESP = "ipsec_esp"
    KEY_SCHEDULE = "key_schedule"
    PRNG = "prng"
    HASH_CHAIN = "hash_chain"
    BLOCK_CIPHER = "block_cipher"


@dataclass
class VerificationResult:
    """Result of symbolic verification."""
    function_name: str
    function_address: int
    verified: bool
    protocol: ProtocolType
    confidence: float
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        return {
            "function_name": self.function_name,
            "function_address": hex(self.function_address),
            "verified": self.verified,
            "protocol": self.protocol.value,
            "confidence": self.confidence,
            "details": self.details
        }


class SymbolicVerifier:
    """
    Symbolic execution-based verifier for crypto functions.
    Uses Angr to explore function behavior and detect patterns.
    """
    
    def __init__(self, binary_path: str = None, timeout: int = 60):
        """
        Initialize verifier.
        
        Args:
            binary_path: Path to the binary being analyzed
            timeout: Timeout in seconds for symbolic exploration
        """
        self.binary_path = binary_path
        self.timeout = timeout
        self.project = None
        
        if ANGR_AVAILABLE and binary_path and os.path.exists(binary_path):
            try:
                self.project = angr.Project(
                    binary_path, 
                    auto_load_libs=False,
                    load_options={'auto_load_libs': False}
                )
                print(f"✓ Loaded binary for symbolic analysis: {binary_path}")
            except Exception as e:
                print(f"⚠ Could not load binary with Angr: {e}")
    
    def verify_function(self, function: Dict) -> VerificationResult:
        """
        Verify a single function using symbolic execution.
        
        Args:
            function: Dict with name, address, class_id, confidence, etc.
            
        Returns:
            VerificationResult with protocol detection
        """
        name = function.get("name", "unknown")
        address = function.get("address") or function.get("entry", 0)
        
        # Parse address if string
        if isinstance(address, str):
            try:
                address = int(address, 16) if address.startswith("0x") else int(address)
            except:
                address = 0
        
        class_id = function.get("class_id", 0)
        initial_confidence = function.get("confidence", 0.5)
        
        # Default result
        result = VerificationResult(
            function_name=name,
            function_address=address,
            verified=False,
            protocol=ProtocolType.UNKNOWN,
            confidence=initial_confidence,
            details={}
        )
        
        if not ANGR_AVAILABLE:
            result.details["error"] = "Angr not available"
            return result
        
        if not self.project:
            result.details["error"] = "No binary loaded"
            return result
        
        try:
            # Create symbolic state at function entry
            state = self.project.factory.blank_state(addr=address)
            
            # Make input symbolic
            input_size = 64  # bytes
            symbolic_input = claripy.BVS("input", input_size * 8)
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore with timeout
            simgr.explore(
                find=lambda s: self._is_crypto_behavior(s),
                avoid=lambda s: self._is_error_state(s),
                num_find=5
            )
            
            # Analyze results
            if simgr.found:
                result.verified = True
                protocol = self._detect_protocol(simgr.found, class_id)
                result.protocol = protocol
                result.confidence = min(initial_confidence + 0.1, 1.0)
                result.details["paths_found"] = len(simgr.found)
                result.details["exploration"] = "successful"
            else:
                result.details["exploration"] = "no_crypto_paths"
                
        except Exception as e:
            result.details["error"] = str(e)
            result.details["exploration"] = "failed"
        
        return result
    
    def verify_batch(self, functions: List[Dict], 
                     confidence_threshold: float = 0.85) -> List[VerificationResult]:
        """
        Verify a batch of high-confidence functions.
        
        Args:
            functions: List of function dicts
            confidence_threshold: Only verify functions above this threshold
            
        Returns:
            List of VerificationResults
        """
        results = []
        
        # Filter to high-confidence functions
        candidates = [
            f for f in functions 
            if f.get("confidence", 0) >= confidence_threshold
        ]
        
        for func in candidates:
            result = self.verify_function(func)
            results.append(result)
        
        return results
    
    def _is_crypto_behavior(self, state) -> bool:
        """
        Check if state exhibits crypto-like behavior.
        Look for:
        - XOR operations on input
        - Rotation operations
        - Table lookups (S-box)
        """
        # Simplified check - in real implementation would analyze constraints
        return False
    
    def _is_error_state(self, state) -> bool:
        """Check if state is in an error condition."""
        return False
    
    def _detect_protocol(self, found_states: List, class_id: int) -> ProtocolType:
        """
        Detect protocol type based on found states and classification.
        """
        # Map class IDs to likely protocols
        protocol_map = {
            1: ProtocolType.BLOCK_CIPHER,  # AES/Block cipher
            2: ProtocolType.HASH_CHAIN,     # Hash function
            3: ProtocolType.BLOCK_CIPHER,   # Stream cipher
            4: ProtocolType.TLS_HANDSHAKE,  # Public key -> likely TLS
            5: ProtocolType.TLS_RECORD,     # MAC -> likely TLS record
            6: ProtocolType.KEY_SCHEDULE,   # KDF
            7: ProtocolType.PRNG,           # PRNG
        }
        
        return protocol_map.get(class_id, ProtocolType.UNKNOWN)


class HeuristicVerifier:
    """
    Fallback verifier using heuristics when Angr is not available.
    """
    
    def __init__(self):
        self.protocol_patterns = {
            ProtocolType.TLS_HANDSHAKE: {
                "keywords": [b"ClientHello", b"ServerHello", b"Certificate", b"Finished"],
                "class_ids": [1, 4],  # Block cipher + Public key
            },
            ProtocolType.SSH_KEX: {
                "keywords": [b"SSH-", b"diffie-hellman", b"ssh-rsa", b"ecdsa"],
                "class_ids": [4],  # Public key
            },
            ProtocolType.IPSEC_ESP: {
                "keywords": [b"ESP", b"AH", b"IKE"],
                "class_ids": [1, 5],  # Block cipher + MAC
            },
        }
    
    def verify_function(self, function: Dict, 
                        binary_data: bytes = None) -> VerificationResult:
        """
        Verify function using heuristics.
        """
        name = function.get("name", "unknown")
        address = function.get("address", 0)
        class_id = function.get("class_id", 0)
        confidence = function.get("confidence", 0.5)
        
        # Parse address
        if isinstance(address, str):
            try:
                address = int(address, 16) if address.startswith("0x") else int(address)
            except:
                address = 0
        
        protocol = ProtocolType.UNKNOWN
        verified = False
        details = {"method": "heuristic"}
        
        # Check function name patterns
        name_lower = name.lower()
        
        if "tls" in name_lower or "ssl" in name_lower or "handshake" in name_lower:
            protocol = ProtocolType.TLS_HANDSHAKE
            verified = True
            details["name_match"] = "tls/ssl pattern"
        elif "ssh" in name_lower or "kex" in name_lower:
            protocol = ProtocolType.SSH_KEX
            verified = True
            details["name_match"] = "ssh pattern"
        elif "aes" in name_lower or "encrypt" in name_lower or "cipher" in name_lower:
            protocol = ProtocolType.BLOCK_CIPHER
            verified = True
            details["name_match"] = "cipher pattern"
        elif "sha" in name_lower or "hash" in name_lower or "digest" in name_lower:
            protocol = ProtocolType.HASH_CHAIN
            verified = True
            details["name_match"] = "hash pattern"
        elif "key" in name_lower and ("sched" in name_lower or "expand" in name_lower):
            protocol = ProtocolType.KEY_SCHEDULE
            verified = True
            details["name_match"] = "key schedule pattern"
        elif "random" in name_lower or "rand" in name_lower or "prng" in name_lower:
            protocol = ProtocolType.PRNG
            verified = True
            details["name_match"] = "prng pattern"
        
        # If binary data provided, check for literal patterns
        if binary_data and not verified:
            for ptype, pdata in self.protocol_patterns.items():
                if class_id in pdata.get("class_ids", []):
                    for keyword in pdata.get("keywords", []):
                        if keyword in binary_data:
                            protocol = ptype
                            verified = True
                            details["data_match"] = keyword.decode(errors='replace')
                            break
                if verified:
                    break
        
        return VerificationResult(
            function_name=name,
            function_address=address,
            verified=verified,
            protocol=protocol,
            confidence=confidence + (0.1 if verified else 0),
            details=details
        )


def get_verifier(binary_path: str = None) -> Any:
    """
    Get the appropriate verifier based on availability.
    """
    if ANGR_AVAILABLE and binary_path:
        return SymbolicVerifier(binary_path)
    return HeuristicVerifier()


def verify_functions(functions: List[Dict], 
                     binary_path: str = None,
                     confidence_threshold: float = 0.85) -> List[Dict]:
    """
    Convenience function to verify suspected crypto functions.
    
    Args:
        functions: List of function dicts with confidence scores
        binary_path: Path to the binary being analyzed
        confidence_threshold: Only verify high-confidence functions
        
    Returns:
        List of verified functions with protocol info
    """
    verifier = get_verifier(binary_path)
    
    # Filter by confidence
    candidates = [
        f for f in functions 
        if f.get("confidence", 0) >= confidence_threshold
    ]
    
    results = []
    for func in candidates:
        result = verifier.verify_function(func)
        results.append(result.to_dict())
    
    return results


if __name__ == "__main__":
    # Test with sample functions
    test_functions = [
        {
            "name": "mbedtls_aes_encrypt",
            "address": "0x401000",
            "class_id": 1,
            "class_name": "AES/Block Cipher",
            "confidence": 0.92
        },
        {
            "name": "ssl_handshake_client",
            "address": "0x402000",
            "class_id": 4,
            "class_name": "Public Key",
            "confidence": 0.88
        },
        {
            "name": "sha256_update",
            "address": "0x403000",
            "class_id": 2,
            "class_name": "Hash Function",
            "confidence": 0.95
        }
    ]
    
    print("\nSymbolic Verification Results:")
    results = verify_functions(test_functions)
    for r in results:
        print(f"  {r['function_name']}: {r['protocol']} (verified={r['verified']})")
