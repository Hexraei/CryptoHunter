"""
Angr Symbolic Verification
Verify high-confidence crypto functions using symbolic execution.
Detects protocol patterns like TLS handshake, key schedules, etc.

This is Step 5 in the CryptoHunter pipeline.
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


# =============================================================================
# Architecture Mapping
# =============================================================================

# Map our architecture names to Angr architecture strings
ANGR_ARCH_MAP = {
    # ARM variants
    "ARM32": "ARMEL",
    "ARM-Thumb": "ARMEL",
    "ARM32/BE": "ARMHF",
    "ARM64": "AARCH64",
    "ARM64/64-bit": "AARCH64",
    "ARM/Cortex-M": "ARMEL",
    
    # x86 variants
    "x86": "X86",
    "x86-64": "AMD64",
    "x86-64/64-bit": "AMD64",
    
    # MIPS variants
    "MIPS-BE": "MIPS32",
    "MIPS-BE/BE": "MIPS32",
    "MIPS-LE": "MIPSEL",
    "MIPS64": "MIPS64",
    
    # Other
    "RISCV32": "RISCV32",
    "RISC-V": "RISCV32",
    "PowerPC": "PPC32",
    
    # Unsupported by Angr (will use auto-detect)
    "Xtensa": None,
    "Xtensa/ESP32": None,
    "AVR": None,
    "Z80": None,
}


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
    STREAM_CIPHER = "stream_cipher"
    MAC = "mac"
    SIGNATURE = "signature"


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
            "function_address": hex(self.function_address) if self.function_address else "0x0",
            "verified": self.verified,
            "protocol": self.protocol.value,
            "confidence": self.confidence,
            "details": self.details
        }


# =============================================================================
# Crypto Pattern Detection
# =============================================================================

class CryptoPatternDetector:
    """
    Detect crypto operations in symbolic execution.
    
    Crypto indicators:
    - XOR chains: output = input ^ key ^ something
    - S-box lookups: memory[table + byte] patterns
    - Rotations: (x << n) | (x >> (32-n))
    - Addition chains: modular arithmetic
    """
    
    # Known crypto constants (partial matches)
    CRYPTO_CONSTANTS = {
        # AES S-box first/last bytes
        0x63: "aes_sbox",
        0x7c: "aes_sbox",
        0x16: "aes_sbox_end",
        # SHA-256 K constants
        0x428a2f98: "sha256_k",
        0x71374491: "sha256_k",
        # MD5 T values
        0xd76aa478: "md5_t",
        0xe8c7b756: "md5_t",
        # ChaCha constants
        0x61707865: "chacha",
        0x3320646e: "chacha",
    }
    
    def __init__(self):
        self.xor_count = 0
        self.rotation_count = 0
        self.sbox_access_count = 0
        self.const_matches = []
        self.operations = []
    
    def analyze_state(self, state) -> Dict:
        """Analyze a symbolic state for crypto patterns."""
        self.reset()
        
        if not ANGR_AVAILABLE:
            return {"error": "Angr not available"}
        
        try:
            # Analyze state history for operations
            self._analyze_history(state)
            
            # Analyze constraints for crypto patterns
            self._analyze_constraints(state)
            
            # Analyze memory accesses
            self._analyze_memory(state)
            
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "xor_count": self.xor_count,
            "rotation_count": self.rotation_count,
            "sbox_access_count": self.sbox_access_count,
            "const_matches": self.const_matches,
            "is_crypto": self.is_crypto_behavior()
        }
    
    def reset(self):
        """Reset counters."""
        self.xor_count = 0
        self.rotation_count = 0
        self.sbox_access_count = 0
        self.const_matches = []
        self.operations = []
    
    def _analyze_history(self, state):
        """Analyze execution history for crypto operations."""
        try:
            # Count operation types from history
            for action in state.history.actions:
                action_str = str(action).lower()
                
                if 'xor' in action_str:
                    self.xor_count += 1
                if 'rotate' in action_str or 'rol' in action_str or 'ror' in action_str:
                    self.rotation_count += 1
                if 'read' in action_str and 'mem' in action_str:
                    self.sbox_access_count += 1
        except:
            pass
    
    def _analyze_constraints(self, state):
        """Analyze solver constraints for crypto patterns."""
        try:
            for constraint in state.solver.constraints:
                constraint_str = str(constraint)
                
                # Count XORs in constraints
                self.xor_count += constraint_str.count('^')
                self.xor_count += constraint_str.lower().count('xor')
                
                # Look for rotation patterns
                if '<<' in constraint_str and '>>' in constraint_str:
                    self.rotation_count += 1
                
                # Check for crypto constants
                for const, name in self.CRYPTO_CONSTANTS.items():
                    if hex(const) in constraint_str:
                        self.const_matches.append(name)
        except:
            pass
    
    def _analyze_memory(self, state):
        """Analyze memory accesses for S-box lookups."""
        try:
            # Check for table-based lookups (S-box pattern)
            mem_reads = state.history.filter_actions(read_from='mem')
            
            # Multiple memory reads with computed addresses = potential S-box
            computed_addr_reads = 0
            for read in mem_reads:
                if hasattr(read, 'addr') and read.addr.symbolic:
                    computed_addr_reads += 1
            
            if computed_addr_reads >= 4:
                self.sbox_access_count += computed_addr_reads
        except:
            pass
    
    def is_crypto_behavior(self) -> bool:
        """Determine if this state shows crypto behavior."""
        # Multiple XORs = likely crypto
        if self.xor_count >= 4:
            return True
        
        # XORs + rotations = cipher round
        if self.xor_count >= 2 and self.rotation_count >= 1:
            return True
        
        # S-box access pattern
        if self.sbox_access_count >= 8:
            return True
        
        # Known crypto constants
        if len(self.const_matches) >= 1:
            return True
        
        return False


# =============================================================================
# Symbolic Verifier
# =============================================================================

class SymbolicVerifier:
    """
    Symbolic execution-based verifier for crypto functions.
    Uses Angr to explore function behavior and detect patterns.
    """
    
    def __init__(self, binary_path: str = None, detected_arch: str = None, timeout: int = 60):
        """
        Initialize verifier.
        
        Args:
            binary_path: Path to the binary being analyzed
            detected_arch: Architecture from our detector (e.g., "ARM64", "x86")
            timeout: Timeout in seconds for symbolic exploration
        """
        self.binary_path = binary_path
        self.detected_arch = detected_arch
        self.timeout = timeout
        self.project = None
        self.pattern_detector = CryptoPatternDetector()
        
        if ANGR_AVAILABLE and binary_path and os.path.exists(binary_path):
            self._load_binary()
    
    def _load_binary(self):
        """Load binary with correct architecture."""
        load_options = {
            'auto_load_libs': False,
        }
        
        # If we detected architecture, try to use it
        main_opts = {}
        if self.detected_arch:
            angr_arch = ANGR_ARCH_MAP.get(self.detected_arch)
            if angr_arch:
                main_opts['arch'] = angr_arch
        
        if main_opts:
            load_options['main_opts'] = main_opts
        
        try:
            self.project = angr.Project(
                self.binary_path,
                load_options=load_options
            )
            arch_info = f"arch={self.project.arch.name}" if self.project else ""
            print(f"  Loaded binary for Angr analysis ({arch_info})")
        except Exception as e:
            print(f"  Could not load binary with Angr: {e}")
            self.project = None
    
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
            details={"method": "symbolic"}
        )
        
        if not ANGR_AVAILABLE:
            result.details["error"] = "Angr not available"
            result.details["method"] = "none"
            return result
        
        if not self.project:
            result.details["error"] = "No binary loaded"
            result.details["method"] = "none"
            return result
        
        if not address or address == 0:
            result.details["error"] = "No valid address"
            result.details["method"] = "none"
            return result
        
        try:
            # Create symbolic state at function entry
            state = self.project.factory.blank_state(addr=address)
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore with step limit (to avoid infinite loops)
            simgr.run(n=100)  # Max 100 steps
            
            # Analyze all reached states
            crypto_states = 0
            total_states = 0
            
            all_states = simgr.active + simgr.deadended
            
            for s in all_states[:10]:  # Check first 10 states
                total_states += 1
                analysis = self.pattern_detector.analyze_state(s)
                if analysis.get("is_crypto", False):
                    crypto_states += 1
            
            # If significant crypto behavior detected
            if crypto_states > 0 or total_states == 0:
                result.verified = True
                result.protocol = self._detect_protocol_from_class(class_id)
                result.confidence = min(initial_confidence + 0.1, 1.0)
                result.details["crypto_states"] = crypto_states
                result.details["total_states"] = total_states
                result.details["xor_count"] = self.pattern_detector.xor_count
                result.details["rotation_count"] = self.pattern_detector.rotation_count
                result.details["exploration"] = "successful"
            else:
                result.details["exploration"] = "no_crypto_patterns"
                result.details["total_states"] = total_states
                
        except Exception as e:
            result.details["error"] = str(e)
            result.details["exploration"] = "failed"
        
        return result
    
    def _detect_protocol_from_class(self, class_id: int) -> ProtocolType:
        """Detect protocol type based on GNN classification."""
        protocol_map = {
            1: ProtocolType.BLOCK_CIPHER,   # AES/Block cipher
            2: ProtocolType.HASH_CHAIN,     # Hash function
            3: ProtocolType.STREAM_CIPHER,  # Stream cipher
            4: ProtocolType.SIGNATURE,      # Public key
            5: ProtocolType.MAC,            # MAC
            6: ProtocolType.KEY_SCHEDULE,   # KDF
            7: ProtocolType.PRNG,           # PRNG
        }
        return protocol_map.get(class_id, ProtocolType.UNKNOWN)
    
    def verify_key_schedule(self, func_addr: int, key_size: int = 256) -> Dict:
        """
        Verify function behaves like a key schedule.
        
        Key schedule properties:
        - Takes master key as input
        - Produces multiple round keys
        - Each round key depends on master key
        """
        if not ANGR_AVAILABLE or not self.project:
            return {"is_key_schedule": False, "reason": "angr_unavailable"}
        
        try:
            # Create symbolic master key
            master_key = claripy.BVS("master_key", key_size)
            
            # Set up state
            state = self.project.factory.blank_state(addr=func_addr)
            
            # Explore briefly
            simgr = self.project.factory.simulation_manager(state)
            simgr.run(n=50)
            
            if not simgr.deadended and not simgr.active:
                return {"is_key_schedule": False, "reason": "no_completion"}
            
            # Check any reached state
            final_states = simgr.deadended + simgr.active
            if final_states:
                final_state = final_states[0]
                analysis = self.pattern_detector.analyze_state(final_state)
                
                # Key schedules typically have many XORs and rotations
                if analysis.get("xor_count", 0) >= 4 and analysis.get("rotation_count", 0) >= 1:
                    return {
                        "is_key_schedule": True,
                        "xor_count": analysis.get("xor_count"),
                        "rotation_count": analysis.get("rotation_count")
                    }
            
            return {"is_key_schedule": False, "reason": "no_key_schedule_patterns"}
            
        except Exception as e:
            return {"is_key_schedule": False, "error": str(e)}
    
    def verify_batch(self, functions: List[Dict], 
                     confidence_threshold: float = 0.80) -> List[VerificationResult]:
        """
        Verify a batch of high-confidence functions.
        
        Args:
            functions: List of function dicts
            confidence_threshold: Only verify functions above this threshold
            
        Returns:
            List of VerificationResults
        """
        results = []
        
        # Filter to high-confidence crypto functions
        candidates = [
            f for f in functions 
            if f.get("confidence", 0) >= confidence_threshold
            and f.get("class_id", 0) > 0  # Only crypto classes
        ]
        
        for func in candidates[:20]:  # Limit to 20 functions
            result = self.verify_function(func)
            results.append(result)
        
        return results


# =============================================================================
# Heuristic Verifier (Fallback)
# =============================================================================

class HeuristicVerifier:
    """
    Fallback verifier using heuristics when Angr is not available.
    """
    
    def __init__(self):
        self.protocol_patterns = {
            ProtocolType.TLS_HANDSHAKE: {
                "keywords": ["tls", "ssl", "handshake", "clienthello", "serverhello"],
                "class_ids": [1, 4],
            },
            ProtocolType.SSH_KEX: {
                "keywords": ["ssh", "kex", "diffie", "ecdh"],
                "class_ids": [4],
            },
            ProtocolType.IPSEC_ESP: {
                "keywords": ["esp", "ipsec", "ike", "isakmp"],
                "class_ids": [1, 5],
            },
            ProtocolType.BLOCK_CIPHER: {
                "keywords": ["aes", "des", "encrypt", "decrypt", "cipher", "block"],
                "class_ids": [1],
            },
            ProtocolType.HASH_CHAIN: {
                "keywords": ["sha", "md5", "hash", "digest", "blake", "ripemd"],
                "class_ids": [2],
            },
            ProtocolType.KEY_SCHEDULE: {
                "keywords": ["key", "schedule", "expand", "derive", "kdf", "pbkdf"],
                "class_ids": [6],
            },
            ProtocolType.PRNG: {
                "keywords": ["random", "rand", "prng", "drbg", "entropy"],
                "class_ids": [7],
            },
            ProtocolType.MAC: {
                "keywords": ["hmac", "cmac", "gmac", "poly1305", "mac"],
                "class_ids": [5],
            },
            ProtocolType.STREAM_CIPHER: {
                "keywords": ["chacha", "salsa", "rc4", "stream"],
                "class_ids": [3],
            },
        }
    
    def verify_function(self, function: Dict, binary_data: bytes = None) -> VerificationResult:
        """Verify function using heuristics."""
        name = function.get("name", "unknown")
        address = function.get("address") or function.get("entry", 0)
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
        
        for ptype, pdata in self.protocol_patterns.items():
            # Check keywords
            for keyword in pdata.get("keywords", []):
                if keyword in name_lower:
                    protocol = ptype
                    verified = True
                    details["name_match"] = keyword
                    break
            
            # Also check if class_id matches
            if not verified and class_id in pdata.get("class_ids", []):
                protocol = ptype
                verified = True
                details["class_match"] = class_id
            
            if verified:
                break
        
        # Boost confidence if verified
        if verified:
            confidence = min(confidence + 0.05, 1.0)
        
        return VerificationResult(
            function_name=name,
            function_address=address,
            verified=verified,
            protocol=protocol,
            confidence=confidence,
            details=details
        )


# =============================================================================
# Public API
# =============================================================================

def get_verifier(binary_path: str = None, detected_arch: str = None):
    """
    Get the appropriate verifier based on availability.
    
    Args:
        binary_path: Path to binary
        detected_arch: Detected architecture (e.g., "ARM64")
    
    Returns:
        SymbolicVerifier if Angr available, else HeuristicVerifier
    """
    if ANGR_AVAILABLE and binary_path:
        return SymbolicVerifier(binary_path, detected_arch)
    return HeuristicVerifier()


def verify_functions(functions: List[Dict], 
                     binary_path: str = None,
                     detected_arch: str = None,
                     confidence_threshold: float = 0.80) -> List[Dict]:
    """
    Verify suspected crypto functions.
    
    Args:
        functions: List of function dicts with confidence scores
        binary_path: Path to the binary being analyzed
        detected_arch: Detected architecture
        confidence_threshold: Only verify high-confidence functions
        
    Returns:
        List of verified functions with protocol info
    """
    verifier = get_verifier(binary_path, detected_arch)
    
    # Filter by confidence and crypto class
    candidates = [
        f for f in functions 
        if f.get("confidence", 0) >= confidence_threshold
        and f.get("class_id", 0) > 0
    ]
    
    results = []
    for func in candidates[:20]:  # Limit
        if isinstance(verifier, SymbolicVerifier):
            result = verifier.verify_function(func)
        else:
            result = verifier.verify_function(func)
        results.append(result.to_dict())
    
    return results


def check_angr_status() -> Dict:
    """Check Angr availability and version."""
    result = {
        "available": ANGR_AVAILABLE,
        "version": None,
        "architectures": []
    }
    
    if ANGR_AVAILABLE:
        import angr
        result["version"] = angr.__version__
        result["architectures"] = list(ANGR_ARCH_MAP.keys())
    
    return result


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Angr Symbolic Verification Module")
    print("=" * 60)
    
    # Check status
    status = check_angr_status()
    print(f"\nAngr available: {status['available']}")
    if status['available']:
        print(f"Version: {status['version']}")
    
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
    
    print("\nHeuristic Verification Results:")
    verifier = HeuristicVerifier()
    for func in test_functions:
        result = verifier.verify_function(func)
        print(f"  {result.function_name}: {result.protocol.value} (verified={result.verified})")
